//! BFV Parameter Search Library
//!
//! This library provides functionality to search for optimal BFV (Brakerski-Fan-Vercauteren)
//! parameters using NTT-friendly primes. It implements exact arithmetic for security analysis
//! and parameter validation.
use crate::constants::{D_POW2_MAX, D_POW2_START, K_MAX};
use crate::errors::{BfvParamsResult, SearchError, ValidationError};
use crate::prime::PrimeItem;
use crate::prime::build_prime_items;
use crate::prime::select_crt_primes_one_pack;
use crate::utils::{approx_bits_from_log2, big_shift_pow2, fmt_big_summary, log2_big, product};
use num_bigint::BigUint;
use num_traits::ToPrimitive;

/// Configuration for BFV parameter search
#[derive(Debug, Clone)]
pub struct BfvSearchConfig {
    /// Number of parties n (e.g. ciphernodes)
    pub n: u128,
    /// Number of fresh ciphertext additions z (number of votes) - equal to k_plain_eff.
    pub z: u128,
    /// Statistical Security parameter λ (negl(λ)=2^{-λ})
    pub lambda: u32,
    /// Bound B on the error distribution ψ used generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    pub b: u128,
    /// Bound B_{\chi} on the distribution \chi used generate the secret key sk_i of each party i.
    pub b_chi: u128,
    /// Verbose output showing detailed parameter search process
    pub verbose: bool,
}

/// Result of BFV parameter search
#[derive(Debug, Clone)]
pub struct BfvSearchResult {
    /// Chosen degree and primes
    pub d: u64,
    pub k_plain_eff: u128, // = z
    pub q_bfv: BigUint,
    pub selected_primes: Vec<PrimeItem>,
    pub rkq: u128,
    pub delta: BigUint,

    /// Noise budgets
    pub benc_min: BigUint,
    pub b_fresh: BigUint,
    pub b_c: BigUint,
    pub b_sm_min: BigUint,

    /// Validation logs
    pub lhs_log2: f64,
    pub rhs_log2: f64,
}

impl BfvSearchResult {
    /// Extract prime values as u64 for BFV parameter construction
    pub fn qi_values(&self) -> Vec<u64> {
        self.selected_primes
            .iter()
            .map(|p| p.value.to_u64().expect("Prime value too large for u64"))
            .collect()
    }
}

pub fn bfv_search(bfv_search_config: &BfvSearchConfig) -> BfvParamsResult<BfvSearchResult> {
    let prime_items = build_prime_items();

    // Quick checks on k := z
    if bfv_search_config.z == 0 || bfv_search_config.z > K_MAX {
        return Err(ValidationError::InvalidVotes {
            z: bfv_search_config.z,
            reason: "z must be positive and less than 2^25".to_string(),
        }
        .into());
    }

    let log2_b = (bfv_search_config.b as f64).log2();
    let mut d: u64 = D_POW2_START;

    while d <= D_POW2_MAX {
        // Eq4: d ≥ 37.5*log2(q/B) + 75  =>  log2(q) ≤ log2(B) + (d-75)/37.5
        let log2_q_limit = log2_b + ((d as f64) - 75.0) / 37.5;

        // Select the single best same-size pack under the cap (fewest primes, limit-first)
        let chosen = select_crt_primes_one_pack(log2_q_limit, &prime_items);

        if chosen.is_empty() {
            if bfv_search_config.verbose {
                println!("\n[BFV] d={d} checking for log2_q_limit = {log2_q_limit:.3}).");
                println!(
                    "\n[BFV] d={d} candidate: no CRT primes fit under Eq4 limit (log2 limit {log2_q_limit:.3})."
                );
                println!("  (Consider larger d or smaller n, z, λ, B.)");
            }

            d <<= 1;
            continue;
        }

        // Try this one best candidate; if Eq1 fails, smaller q won't help — increase d.
        match finalize_bfv_candidate(bfv_search_config, d, chosen) {
            Some(res) => {
                return Ok(res);
            }
            None => {
                d <<= 1;
                continue;
            }
        }
    }

    Err(SearchError::NoFeasibleParameters.into())
}

pub fn finalize_bfv_candidate(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
) -> Option<BfvSearchResult> {
    let q_bfv = product(&chosen.iter().map(|pi| pi.value.clone()).collect::<Vec<_>>());

    // r_k(q) = q mod k
    let k_big = BigUint::from(bfv_search_config.z);
    let rkq_big = &q_bfv % &k_big;
    let rkq: u128 = rkq_big.to_u128().unwrap_or(0);

    // Δ = floor(q / k)
    let delta = &q_bfv / &k_big;

    // Eq2: 2 d n B B_chi ≤ B_Enc * 2^{-λ}  =>  B_Enc ≥ (2 d n B B_chi) * 2^{λ}
    let two_pow_lambda = big_shift_pow2(bfv_search_config.lambda);
    let benc_min = (BigUint::from(2u32)
        * BigUint::from(d)
        * BigUint::from(bfv_search_config.n)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi))
        * &two_pow_lambda;

    // B_fresh ≤ B_Enc + d B B_chi+ d B B_chi n
    let term_d_b_chi = BigUint::from(d)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi);
    let term_d_b_b_chi_n = BigUint::from(d)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi)
        * BigUint::from(bfv_search_config.n);
    let b_fresh = &benc_min + &term_d_b_chi + &term_d_b_b_chi_n;

    // B_C = z (B_fresh + r_k(q))
    let b_c = BigUint::from(bfv_search_config.z) * (&b_fresh + BigUint::from(rkq));

    // Eq3: B_C ≤ B_sm * 2^{-λ}  =>  B_sm ≥ B_C * 2^{λ}
    let b_sm_min = &b_c * &two_pow_lambda;

    // Eq1: 2*(B_C + n*B_sm) < Δ
    let lhs = (&b_c + BigUint::from(bfv_search_config.n) * &b_sm_min) << 1;
    let lhs_log2 = log2_big(&lhs);
    let rhs_log2 = log2_big(&delta);

    let benc_bits = approx_bits_from_log2(log2_big(&benc_min));
    let bfresh_bits = approx_bits_from_log2(log2_big(&b_fresh));
    let bc_bits = approx_bits_from_log2(log2_big(&b_c));
    let bsm_bits = approx_bits_from_log2(log2_big(&b_sm_min));

    if bfv_search_config.verbose {
        println!("\n[BFV] d={d} candidate:");
        println!(
            "  CRT primes ({}): {}",
            chosen.len(),
            chosen
                .iter()
                .map(|p| p.hex.clone())
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("  |q_BFV| {}", fmt_big_summary(&q_bfv));
        println!(
            "  r_k(q)={}   k={}   Δ={}",
            rkq,
            bfv_search_config.z,
            delta.to_str_radix(10)
        );

        println!("  negl(λ)=2^-{} (exact pow2)", bfv_search_config.lambda);
        println!("  BEnc ≈ 2^{benc_bits}   B_fresh ≈ 2^{bfresh_bits}");
        println!("  B_C      ≈ 2^{bc_bits}   B_sm ≈ 2^{bsm_bits}");
        println!("  eq1 logs: log2(LHS)≈{lhs_log2:.3}   log2(Δ)≈{rhs_log2:.3}");

        println!(
            "  eq1: 2*(B_C + n*B_sm) {} Δ   => {}",
            if lhs < delta { "<" } else { "≥" },
            if lhs < delta { "PASS ✅" } else { "fail ❌" }
        );

        // Final dump for winning candidate
        println!("\n*** BFV FEASIBLE at d={d} ***");
        println!(
            "BFV qi used ({}): {}",
            chosen.len(),
            chosen
                .iter()
                .map(|p| p.hex.clone())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    if lhs >= delta {
        return None;
    }

    Some(BfvSearchResult {
        d,
        k_plain_eff: bfv_search_config.z,
        q_bfv,
        selected_primes: chosen,
        rkq,
        delta,
        benc_min,
        b_fresh,
        b_c,
        b_sm_min,
        lhs_log2,
        rhs_log2,
    })
}
