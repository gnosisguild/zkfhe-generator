//! BFV Parameter Search Library
//!
//! This library provides functionality to search for optimal BFV (Brakerski-Fan-Vercauteren)
//! parameters using NTT-friendly primes. It implements exact arithmetic for security analysis
//! and parameter validation.
use std::collections::BTreeMap;

use crate::constants::{D_POW2_MAX, D_POW2_START, K_MAX, PlaintextMode};
use crate::errors::{BfvParamsResult, SearchError, ValidationError};
use crate::prime::PrimeItem;
use crate::prime::{build_prime_items, build_prime_items_for_second, select_max_q_under_cap};
use crate::utils::{approx_bits_from_log2, big_shift_pow2, fmt_big_summary, log2_big, product};
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use num_traits::{One, Zero};

/// Configuration for BFV parameter search
#[derive(Debug, Clone)]
pub struct BfvSearchConfig {
    /// Number of parties n (e.g. ciphernodes)
    pub n: u128,
    /// Number of fresh ciphertext additions z (number of votes) - equal to k_plain_eff.
    pub z: u128,
    /// Plaintext modulus k (plaintext space).
    pub k: u128,
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

        if bfv_search_config.verbose {
            println!("\n[BFV] d={d} checking for log2_q_limit = {log2_q_limit:.3}");
        }

        // Build the greedy maximum q under Eq4 cap and test. If it passes, print and start decreasing from this q.
        let initial_sel = select_max_q_under_cap(log2_q_limit, &prime_items);
        if initial_sel.is_empty() {
            if bfv_search_config.verbose {
                println!(
                    "[BFV] d={d} candidate: no CRT primes fit under Eq4 limit (log2 limit {log2_q_limit:.3})."
                );
            }
            d <<= 1;
            continue;
        }

        if let Some(initial_res) = finalize_bfv_candidate(bfv_search_config, d, initial_sel.clone())
        {
            if bfv_search_config.verbose {
                println!("\n--- First feasible before reduction (d={}) ---", d);
                println!(
                    "BFV qi used ({}): {}",
                    initial_res.selected_primes.len(),
                    initial_res
                        .selected_primes
                        .iter()
                        .map(|p| p.hex.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            if let Some(refined) =
                refine_from_initial(bfv_search_config, d, &prime_items, initial_sel)
            {
                return Ok(refined);
            }

            // If refinement fails unexpectedly, return the initial feasible result
            return Ok(initial_res);
        }

        if bfv_search_config.verbose {
            println!(
                "[BFV] d={} : first (largest-q) candidate failed Eq1 — increasing d…",
                d
            );
        }

        d <<= 1;
    }

    Err(SearchError::NoFeasibleParameters.into())
}

pub fn finalize_bfv_candidate(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
) -> Option<BfvSearchResult> {
    let q_bfv = product(&chosen.iter().map(|pi| pi.value.clone()).collect::<Vec<_>>());

    // Compute plaintext space per mode
    let k_plain_eff: u128 = match PlaintextMode::FromQi {
        PlaintextMode::MaxUserAndQi => bfv_search_config.k.max(bfv_search_config.z),
        PlaintextMode::FromQi => bfv_search_config.k.max(bfv_search_config.z),
    };

    // r_k(q) = q mod k
    let k_big = BigUint::from(k_plain_eff);
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
    }

    if lhs >= delta {
        return None;
    }

    Some(BfvSearchResult {
        d,
        k_plain_eff,
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

pub fn refine_from_initial(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    initial_sel: Vec<PrimeItem>,
) -> Option<BfvSearchResult> {
    // Determine initial bits and then decrease by 2 bits per step.
    let initial_q = product(
        &initial_sel
            .iter()
            .map(|pi| pi.value.clone())
            .collect::<Vec<_>>(),
    );
    let mut current_bits = approx_bits_from_log2(log2_big(&initial_q));

    // Start with the initial feasible result
    let mut last_passing = finalize_bfv_candidate(bfv_search_config, d, initial_sel.clone())?;

    // Walk down in steps of 2 bits, keeping the last passing set before the first failure
    while current_bits > 40 {
        let target_bits = current_bits.saturating_sub(2);
        if let Some(res) =
            construct_qi_for_target_bits(bfv_search_config, d, prime_items, target_bits)
        {
            // Update last_passing to this new passing result
            last_passing = res;
            current_bits = target_bits;
            continue;
        } else {
            // Stop at the first failure; return the last passing result
            break;
        }
    }

    Some(last_passing)
}

pub fn construct_qi_for_target_bits(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    target_bits: u64,
) -> Option<BfvSearchResult> {
    // Build buckets sorted ascending (smallest first) to allow tight packing
    let mut by_bits_small: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    let mut by_bits_large: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in prime_items.iter() {
        by_bits_small.entry(p.bitlen).or_default().push(p.clone());
        by_bits_large.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits_small.values_mut() {
        v.sort_by(|a, b| a.value.cmp(&b.value));
    }
    for v in by_bits_large.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }

    let target_f = target_bits as f64;

    // Fewest primes first: start from minimal s needed to reach target with 61-bit primes
    let s = target_bits.div_ceil(61).max(2) as usize;

    let r_float = target_f / (s as f64);
    let floor_r = r_float.floor().clamp(40.0, 61.0) as u8;
    let ceil_r = r_float.ceil().clamp(40.0, 61.0) as u8;

    // Build candidate selections mixing floor/ceil buckets; choose best by closeness once
    let mut tried: Vec<Vec<PrimeItem>> = Vec::new();
    for k in 0..=s {
        let take_ceil = k;
        let take_floor = s - k;
        let mut sel: Vec<PrimeItem> = Vec::new();
        if take_floor > 0 {
            if let Some(b) = by_bits_small.get(&floor_r) {
                if b.len() < take_floor {
                    continue;
                }
                sel.extend(b.iter().take(take_floor).cloned());
            } else {
                continue;
            }
        }
        if take_ceil > 0 {
            if let Some(b) = by_bits_small.get(&ceil_r) {
                if b.len() < take_ceil {
                    continue;
                }
                sel.extend(b.iter().take(take_ceil).cloned());
            } else {
                continue;
            }
        }
        if sel.len() == s {
            tried.push(sel);
        }
    }
    // Also consider pure buckets
    if let Some(b) = by_bits_large.get(&floor_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }
    if let Some(b) = by_bits_large.get(&ceil_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }

    // Pick selection closest to target bits and test exactly once
    let mut best: Option<(f64, Vec<PrimeItem>)> = None;
    for sel in tried {
        let q = product(&sel.iter().map(|pi| pi.value.clone()).collect::<Vec<_>>());
        let qbits = log2_big(&q);
        let diff = (qbits - target_f).abs();
        if let Some((best_diff, _)) = &best {
            if diff < *best_diff {
                best = Some((diff, sel));
            }
        } else {
            best = Some((diff, sel));
        }
    }
    if let Some((_, sel)) = best {
        // During decreasing, use plaintext from qi (not max with user k)
        return finalize_bfv_candidate(bfv_search_config, d, sel.clone());
    }

    None
}

pub fn bfv_search_second_param(
    bfv_search_config: &BfvSearchConfig,
    first: &BfvSearchResult,
) -> Option<BfvSearchResult> {
    // Plaintext space for second set: next power of 2 above max qi of first set.
    let max_qi_bits_first: u64 = first
        .selected_primes
        .iter()
        .map(|pi| pi.value.bits())
        .max()
        .unwrap_or(61);
    let k_second: u128 = if max_qi_bits_first >= 127 {
        u128::MAX
    } else {
        1u128 << ((max_qi_bits_first + 1) as u32)
    };

    if bfv_search_config.verbose {
        println!(
            "Second set: k(plaintext) = {} ({} bits), derived from first max qi = {} bits",
            k_second,
            max_qi_bits_first + 1,
            max_qi_bits_first
        );
    }

    let log2_b = (bfv_search_config.b as f64).log2();
    // Start from the dimension of the first set
    let mut d: u64 = first.d;

    while d <= D_POW2_MAX {
        // Eq4: d ≥ 37.5*log2(q/B) + 75  =>  log2(q) ≤ log2(B) + (d-75)/37.5
        let log2_q_limit = log2_b + ((d as f64) - 75.0) / 37.5;

        if bfv_search_config.verbose {
            println!("\n[BFV-2nd] d={d} checking for log2_q_limit = {log2_q_limit:.3}).");
        }

        // Try decreasing q at this fixed d, collect all passing candidates
        // For second set, use a separate prime pool that includes 62-bit primes
        let prime_items_second = build_prime_items_for_second();
        if let Some(res) = refine_second_param_at_d(
            bfv_search_config,
            d,
            &prime_items_second,
            log2_q_limit,
            k_second,
        ) {
            return Some(res);
        }
        d <<= 1;
    }
    None
}

pub fn refine_second_param_at_d(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    log2_q_limit: f64,
    k_plain: u128,
) -> Option<BfvSearchResult> {
    // Start from largest q under cap at this d and decrease by 2 bits, collecting all passing
    let initial_sel = select_max_q_under_cap(log2_q_limit, prime_items);
    if initial_sel.is_empty() {
        return None;
    }

    let initial_q = product(
        &initial_sel
            .iter()
            .map(|pi| pi.value.clone())
            .collect::<Vec<_>>(),
    );
    let mut current_bits = approx_bits_from_log2(log2_big(&initial_q));
    let mut all_passing: Vec<BfvSearchResult> = Vec::new();

    // Try the initial selection
    if let Some(res) = finalize_second_param(bfv_search_config, d, initial_sel.clone(), k_plain) {
        all_passing.push(res);
    }

    // Decrease by 2 bits at a time, continue even if some fail (don't stop at first failure)
    while current_bits > 40 {
        let target_bits = current_bits.saturating_sub(2);
        if let Some(res) =
            construct_qi_second_param(bfv_search_config, d, prime_items, target_bits, k_plain)
        {
            all_passing.push(res);
        }
        // Continue decreasing regardless of whether this target passed or failed
        current_bits = target_bits;
    }

    // Pick the one with fewest qi's among all passing at this d
    if all_passing.is_empty() {
        return None;
    }
    all_passing.sort_by(|a, b| {
        a.selected_primes.len().cmp(&b.selected_primes.len()).then(
            log2_big(&a.q_bfv)
                .partial_cmp(&log2_big(&b.q_bfv))
                .unwrap_or(std::cmp::Ordering::Equal),
        )
    });
    Some(all_passing.into_iter().next().unwrap())
}

pub fn construct_qi_second_param(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    prime_items: &[PrimeItem],
    target_bits: u64,
    k_plain: u128,
) -> Option<BfvSearchResult> {
    let mut by_bits_small: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    let mut by_bits_large: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in prime_items.iter() {
        by_bits_small.entry(p.bitlen).or_default().push(p.clone());
        by_bits_large.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits_small.values_mut() {
        v.sort_by(|a, b| a.value.cmp(&b.value));
    }
    for v in by_bits_large.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }

    let target_f = target_bits as f64;
    let s = target_bits.div_ceil(62).max(2) as usize;
    let r_float = target_f / (s as f64);
    let floor_r = r_float.floor().clamp(40.0, 62.0) as u8;
    let ceil_r = r_float.ceil().clamp(40.0, 62.0) as u8;

    let mut tried: Vec<Vec<PrimeItem>> = Vec::new();
    for k in 0..=s {
        let take_ceil = k;
        let take_floor = s - k;
        let mut sel: Vec<PrimeItem> = Vec::new();
        if take_floor > 0 {
            if let Some(b) = by_bits_small.get(&floor_r) {
                if b.len() < take_floor {
                    continue;
                }
                sel.extend(b.iter().take(take_floor).cloned());
            } else {
                continue;
            }
        }
        if take_ceil > 0 {
            if let Some(b) = by_bits_small.get(&ceil_r) {
                if b.len() < take_ceil {
                    continue;
                }
                sel.extend(b.iter().take(take_ceil).cloned());
            } else {
                continue;
            }
        }
        if sel.len() == s {
            tried.push(sel);
        }
    }
    if let Some(b) = by_bits_large.get(&floor_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }
    if let Some(b) = by_bits_large.get(&ceil_r) {
        if b.len() >= s {
            tried.push(b.iter().take(s).cloned().collect());
        }
    }

    let mut best: Option<(f64, Vec<PrimeItem>)> = None;
    for sel in tried {
        let q = product(&sel.iter().map(|pi| pi.value.clone()).collect::<Vec<_>>());
        let qbits = log2_big(&q);
        let diff = (qbits - target_f).abs();
        if let Some((best_diff, _)) = &best {
            if diff < *best_diff {
                best = Some((diff, sel));
            }
        } else {
            best = Some((diff, sel));
        }
    }
    if let Some((_, sel)) = best {
        return finalize_second_param(bfv_search_config, d, sel.clone(), k_plain);
    }
    None
}

pub fn finalize_second_param(
    bfv_search_config: &BfvSearchConfig,
    d: u64,
    chosen: Vec<PrimeItem>,
    k_plain: u128,
) -> Option<BfvSearchResult> {
    // Check that all qi are more than one bit larger than k_plain
    // If k_plain = 2^b, then qi must be > 2^{b+1}
    let k_big = BigUint::from(k_plain);
    let k_log2 = if k_plain == 0 {
        0.0
    } else {
        (k_plain as f64).log2()
    };
    let k_bits = if k_plain == 0 {
        0
    } else {
        k_log2.floor() as u64
    };
    let min_qi_threshold = if k_bits >= 127 {
        BigUint::from(u128::MAX)
    } else {
        BigUint::one() << ((k_bits + 1) as u32)
    };

    for pi in &chosen {
        if pi.value <= min_qi_threshold {
            if bfv_search_config.verbose {
                println!(
                    "[BFV-2nd] d={d} candidate rejected: qi {} is not more than one bit larger than k={k_plain} (need > 2^{}).",
                    pi.value,
                    k_bits + 1
                );
            }
            return None;
        }
    }

    let q_bfv = product(&chosen.iter().map(|pi| pi.value.clone()).collect::<Vec<_>>());
    let rkq_big = &q_bfv % &k_big;
    let rkq: u128 = rkq_big.to_u128().unwrap_or(0);
    let delta = &q_bfv / &k_big;

    // For second set: B_Enc = B (simpler), B_fresh = B_Enc + d*B*B_chi + d*B*B_chi
    let benc = BigUint::from(bfv_search_config.b);
    let term_d_bbchi = BigUint::from(d)
        * BigUint::from(bfv_search_config.b)
        * BigUint::from(bfv_search_config.b_chi);
    let b_fresh = &benc + &term_d_bbchi + &term_d_bbchi;
    let b_c = b_fresh.clone(); // B_C = B_fresh

    let lhs = &b_c << 1; // 2*B_C
    let lhs_log2 = log2_big(&lhs);
    let rhs_log2 = log2_big(&delta);

    if bfv_search_config.verbose {
        println!("\n[BFV-2nd] d={d} candidate:");
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
            "  k(plaintext_space)={} Δ={}",
            k_plain,
            delta.to_str_radix(10)
        );
        println!(
            "  BEnc(taken as B) = {}   B_fresh = {}",
            bfv_search_config.b,
            b_fresh.to_str_radix(10)
        );
        println!("  B_C = B_fresh = {}", b_c.to_str_radix(10));
        println!("  log2(2*B_C)≈{:.3}   log2(Δ)≈{:.3}", lhs_log2, rhs_log2);

        let ok = lhs < delta;
        println!(
            "  2*B_C {} Δ   => {}",
            if ok { "<" } else { "≥" },
            if ok { "PASS ✅" } else { "fail ❌" }
        );
        if !ok {
            return None;
        }

        println!("\n*** BFV-2nd FEASIBLE at d={} ***", d);
    }

    Some(BfvSearchResult {
        d,
        k_plain_eff: k_plain,
        q_bfv,
        selected_primes: chosen,
        rkq,
        delta,
        benc_min: benc,
        b_fresh,
        b_c,
        b_sm_min: BigUint::zero(), // not used in second set
        lhs_log2,
        rhs_log2,
    })
}
