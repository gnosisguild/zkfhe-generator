use num_bigint::BigUint;
use std::collections::BTreeMap;

use crate::constants::NTT_PRIMES_BY_BITS;
use crate::errors::{BfvParamsError, SearchError, ValidationError};
use crate::prime::PrimeItem;
use crate::utils::{
    approx_bits_from_log2, big_pow, ceil_to_u128, fmt_big_summary, log2_big, nth_root_floor,
    parse_hex_big, product,
};
use num_integer::Integer;
use num_traits::One;

/// Result type alias for PVW parameter operations
pub type PvwParamsResult<T> = Result<T, BfvParamsError>;

/// Configuration for PVW (Peikert-Vaikuntanathan-Waters) parameter search
///
/// This structure contains all the parameters needed to search for optimal PVW lattice
/// parameters for zero-knowledge proofs. PVW parameters are typically constructed from
/// BFV computation results and define the search space for LWE-based cryptographic
/// parameters including redundancy factors, LWE dimensions, and modulus growth strategies.
#[derive(Debug, Clone)]
pub struct PvwSearchConfig {
    /// Number of parties (e.g., ciphernodes) in the protocol
    pub n: u128,
    /// Starting redundancy parameter ell (power of two, ≥ 2)
    /// The search uses a doubling schedule: ell_start, 2*ell_start, 4*ell_start, ...
    pub ell_start: usize,
    /// Maximum redundancy parameter ell (doubling schedule stops here)
    /// Should be a power of two and ≥ ell_start
    pub ell_max: usize,
    /// Starting LWE dimension k (doubling schedule)
    /// Higher values provide more security but require larger parameters
    pub k_start: usize,
    /// Maximum LWE dimension k (inclusive, typically 32768)
    /// The doubling schedule for k will stop at this value
    pub k_max: usize,
    /// Alpha parameter in Δ = floor(q_PVW^(α/ℓ))
    /// Common choices are 1 or 2, affecting the delta computation for noise analysis
    pub delta_power_num: u32,
    /// Override BFV primes (comma-separated hex or decimal)
    /// If provided, these primes override the computed q_BFV modulus
    /// Example: "0x00800000022a0001,0x00800000021a0001"
    pub qbfv_primes: Option<String>,
    /// Limit for extra PVW prime enumeration beyond q_BFV
    /// Controls how many growth steps to attempt when expanding the modulus
    pub max_pvw_growth: Option<usize>,
    /// Secret key variance for PVW parameters. Default: 0.5 (standard for CBD distribution).
    pub secret_variance: f32,
    /// Enable verbose output showing detailed parameter search process
    pub verbose: bool,
}

/// Result of PVW parameter search
#[derive(Debug, Clone)]
pub struct PvwSearchResult {
    pub ell: usize,
    pub k: usize,
    pub sigma1: u128,
    pub sigma2: u128,
    pub delta_log2: f64,
    pub lhs_log2: f64,
    pub rhs_log2: f64,
    pub q_pvw_bits: u64,
    pub pvw_primes_used: usize,
    pub used_pvw_list: Vec<BigUint>,
}

pub fn group_by_bits() -> BTreeMap<u64, Vec<BigUint>> {
    let mut map: BTreeMap<u64, Vec<_>> = BTreeMap::new();
    for &(bits_tag, hexes) in NTT_PRIMES_BY_BITS.iter() {
        let key = bits_tag as u64;
        for &h in &hexes {
            let p = parse_hex_big(h);
            map.entry(key).or_default().push(p);
        }
    }
    for v in map.values_mut() {
        v.sort();
        v.dedup();
    }
    map
}

pub fn build_tail_pool_for_growth(
    bfv_primes: &[BigUint],
    pvw_by_bits: &BTreeMap<u64, Vec<BigUint>>,
) -> (u64, Vec<BigUint>) {
    let mut target_bits: u64 = u64::MAX;
    for p in bfv_primes {
        target_bits = target_bits.min(p.bits());
    }
    let mut tail: Vec<BigUint> = Vec::new();

    let mut push_group = |bits: u64| {
        if let Some(group) = pvw_by_bits.get(&bits) {
            for p in group {
                if !bfv_primes.iter().any(|q| q == p) {
                    tail.push(p.clone());
                }
            }
        }
    };

    push_group(target_bits);
    for bits in (target_bits + 1)..=63u64 {
        push_group(bits);
    }

    (target_bits, tail)
}

/// Δ = floor(q_PVW^(α/ℓ)), nudged to gcd(Δ,q_PVW)=1, with Δ≥2
pub fn choose_delta(q_pvw: &BigUint, ell: u32, alpha: u32) -> BigUint {
    let root = nth_root_floor(q_pvw, ell);
    let mut delta = if alpha == 1 {
        root
    } else {
        big_pow(&root, alpha as u64)
    };
    if delta < BigUint::from(2u32) {
        delta = BigUint::from(2u32);
    }
    while !delta.gcd(q_pvw).is_one() && delta > BigUint::from(2u32) {
        delta -= BigUint::one();
    }
    delta
}

pub fn correctness_rhs_new(sigma1: u128, n: usize, ell: usize, k: usize) -> f64 {
    let nf = n as f64;
    let ellf = ell as f64;
    let kf = k as f64;
    let s1 = sigma1 as f64;

    let term_a = ellf * (kf * nf).sqrt() * 20973f64.sqrt() * (nf * ellf).sqrt() * (1.0 + nf.sqrt());
    let term_b = 2.0 * kf * ellf;
    let term_c = 14.0 * (nf * kf * ellf).sqrt();

    s1 * (term_a + term_b + term_c)
}

pub fn pvw_search(
    config: &PvwSearchConfig,
    bfv_primes: &[PrimeItem],
) -> PvwParamsResult<PvwSearchResult> {
    if !config.ell_start.is_power_of_two() || config.ell_start < 2 {
        return Err(ValidationError::General {
            message: format!(
                "ell_start must be a power of two and >= 2. Got {}",
                config.ell_start
            ),
        }
        .into());
    }

    let bfv_prime_values: Vec<BigUint> = bfv_primes.iter().map(|pi| pi.value.clone()).collect();
    let q_bfv = product(&bfv_prime_values);

    // Build tail pool (size-aware, excluding BFV primes)
    let pvw_by_bits = group_by_bits();
    let (target_bits, tail_pool) = build_tail_pool_for_growth(&bfv_prime_values, &pvw_by_bits);

    if config.verbose {
        println!("== PVW search starting from BFV q (same CRT primes) ==");
        println!(
            "PVW growth starts at bit-length {target_bits} (min among BFV CRT primes).\nFirst evaluate q_PVW = q_BFV, then grow."
        );
    }

    // Growth enumeration: start with g = 0 as exactly q_PVW = q_BFV
    // TODO make the script not necessarily keep the same modulus q_BFV when increasing q_PVW. That
    // is there no need to keep it. This will allow us to have more flexibility when increasing q_PVW.
    let max_growth_default = 4usize;
    let max_growth = config
        .max_pvw_growth
        .unwrap_or(max_growth_default)
        .min(tail_pool.len());

    let mut hits: Vec<PvwSearchResult> = vec![];
    let mut ell = config.ell_start;

    while ell <= config.ell_max {
        if config.verbose {
            println!("\n-- PVW: ℓ = {ell} --");
        }

        for g in 0..=max_growth {
            // q_PVW_g = q_BFV * product of first g tail primes
            let mut q_pvw_g = q_bfv.clone();
            let mut used_pvw = bfv_prime_values.clone();
            if g > 0 {
                for p in tail_pool.iter().take(g) {
                    q_pvw_g *= p;
                    used_pvw.push(p.clone());
                }
            }

            let log2_qpvw = log2_big(&q_pvw_g);
            if config.verbose {
                println!(
                    "q_PVW (growth g={}): {}  ({} primes total)",
                    g,
                    fmt_big_summary(&q_pvw_g),
                    used_pvw.len()
                );
            }

            // Δ from q_PVW (α = delta_power_num)
            let delta = choose_delta(&q_pvw_g, ell as u32, config.delta_power_num);
            let delta_log2 = log2_big(&delta);

            if config.verbose {
                let db = approx_bits_from_log2(delta_log2);
                if db <= 256 {
                    println!("  Δ = {delta}  ({db} bits)");
                } else {
                    println!("  Δ ≈ 2^{db}  ({db} bits)");
                }
            }

            // k loop (doubling)
            let mut k = config.k_start.max(1);

            while k <= config.k_max {
                // Security: kℓ ≥ 37.5*log2(q_PVW/σ1) + 7  =>  log2 σ1 ≥ log2 q_PVW - (kℓ-7)/37.5
                let t_sec = ((k * ell) as f64 - 7.0) / 37.5;
                let log2_sigma1_min = log2_qpvw - t_sec;
                let sigma1_min_real = f64::exp2(log2_sigma1_min);
                let sigma1_int: u128 = if sigma1_min_real <= 1.0 {
                    1
                } else {
                    sigma1_min_real.ceil() as u128
                };

                // Flooding: σ2 = ceil( sqrt(20973) * ℓ * sqrt(k*n) * σ1 )
                let sigma2_real = 20973f64.sqrt()
                    * (ell as f64)
                    * ((k as f64) * (config.n as f64)).sqrt()
                    * (sigma1_int as f64);
                let sigma2_int: u128 = ceil_to_u128(sigma2_real);

                // Correctness via logs:
                let rhs = correctness_rhs_new(sigma1_int, config.n as usize, ell, k);
                let lhs_log2 = (ell as f64 - 1.0) * delta_log2;
                let rhs_log2 = rhs.log2();

                if config.verbose {
                    println!(
                        "[ℓ={ell} g={g} k={:<5}] σ1_int={sigma1_int}  σ2={sigma2_int}  (ℓ-1)·log2(Δ)={lhs_log2:.3}  log2(rhs)={rhs_log2:.3}  => {}",
                        k,
                        if lhs_log2 > rhs_log2 + 1e-12 {
                            "PASS ✅"
                        } else {
                            "fail ❌"
                        }
                    );
                }

                if lhs_log2 > rhs_log2 + 1e-12 {
                    // Found a valid parameter set
                    hits.push(PvwSearchResult {
                        ell,
                        k,
                        sigma1: sigma1_int,
                        sigma2: sigma2_int,
                        delta_log2,
                        lhs_log2,
                        rhs_log2,
                        q_pvw_bits: approx_bits_from_log2(log2_qpvw),
                        pvw_primes_used: used_pvw.len(),
                        used_pvw_list: used_pvw.clone(),
                    });
                }

                if k > config.k_max / 2 {
                    break;
                }
                k *= 2;
            }
        }

        ell <<= 1;
    }

    if hits.is_empty() {
        return Err(SearchError::NoFeasibleParameters.into());
    }

    // Sort: fewest primes, then smaller ℓ, then smaller k
    hits.sort_by(|a, b| {
        a.pvw_primes_used
            .cmp(&b.pvw_primes_used)
            .then(a.ell.cmp(&b.ell))
            .then(a.k.cmp(&b.k))
    });

    if config.verbose {
        println!("\n=== PVW Passing candidates (summary) ===");
        println!("n  ℓ    k      |q_PVW|  PVW#   σ1     σ2        (ℓ-1)·log2(Δ)   log2(rhs)");
        for h in &hits {
            println!(
                "{:<2} {:<4} {:<6} {:>6} {:>5}  {:>11} {:>11}    {:>14.3}   {:>9.3}",
                config.n,
                h.ell,
                h.k,
                h.q_pvw_bits,
                h.pvw_primes_used,
                h.sigma1,
                h.sigma2,
                h.lhs_log2,
                h.rhs_log2
            );
        }

        println!("\n=== PVW Top picks ===");
        for (i, h) in hits.iter().take(5).enumerate() {
            println!(
                "\n#{}  n={}  ℓ={}  k={}  |q_PVW|≈{} bits  PVW_primes_used={}",
                i + 1,
                config.n,
                h.ell,
                h.k,
                h.q_pvw_bits,
                h.pvw_primes_used
            );
            println!("   sigma_e1 = {}", h.sigma1);
            println!("   sigma_e2      = {}", h.sigma2);
            println!(
                "   Check: (ℓ-1)·log2(Δ) = {:.3}  >  log2(rhs) = {:.3}",
                h.lhs_log2, h.rhs_log2
            );
            println!("   PVW primes used:");
            for p in &h.used_pvw_list {
                println!(
                    "     - {}  (hex 0x{})  ({} bits)",
                    p,
                    p.to_str_radix(16),
                    approx_bits_from_log2(log2_big(p))
                );
            }
            println!("secret key: Uniform from {{-1,0,1}}");
        }

        // Always include an ℓ = 8 pick if available
        if let Some((idx, h8)) =
            hits.iter()
                .enumerate()
                .filter(|(_, h)| h.ell == 8)
                .min_by(|(_, a), (_, b)| {
                    a.pvw_primes_used
                        .cmp(&b.pvw_primes_used)
                        .then(a.k.cmp(&b.k))
                })
        {
            // Check if it was already within top 5
            if idx >= 5 {
                println!(
                    "\n#ℓ=8 pick  n={}  ℓ={}  k={}  |q_PVW|≈{} bits  PVW_primes_used={}",
                    config.n, h8.ell, h8.k, h8.q_pvw_bits, h8.pvw_primes_used
                );
                println!("   sigma_e1 = {}", h8.sigma1);
                println!("   sigma_e2      = {}", h8.sigma2);
                println!(
                    "   Check: (ℓ-1)·log2(Δ) = {:.3}  >  log2(rhs) = {:.3}",
                    h8.lhs_log2, h8.rhs_log2
                );
                println!("   PVW primes used:");
                for p in &h8.used_pvw_list {
                    println!(
                        "     - {}  (hex 0x{})  ({} bits)",
                        p,
                        p.to_str_radix(16),
                        approx_bits_from_log2(log2_big(p))
                    );
                }
                println!("secret key: Uniform from {{-1,0,1}}");
            }
        }
    }

    // Prefer ℓ = 8 pick if available, otherwise return the best candidate (first in sorted list)
    let final_result = hits
        .iter()
        .find(|h| h.ell == 8)
        .cloned()
        .unwrap_or_else(|| hits.into_iter().next().unwrap());

    Ok(final_result)
}
