use num_bigint::BigUint;
use std::cmp::Ordering;

use crate::constants::NTT_PRIMES_BY_BITS;
use crate::utils::{log2_big, parse_hex_big};

#[derive(Debug, Clone)]
pub struct PrimeItem {
    pub bitlen: u8,
    pub value: BigUint,
    pub log2: f64,
    pub hex: String,
}

/// Build a flat list of all primes with precomputed log2 and hex strings.
pub fn build_prime_items() -> Vec<PrimeItem> {
    let mut vec = Vec::new();
    for (bits, arr) in NTT_PRIMES_BY_BITS.iter() {
        for &phex in arr {
            let v = parse_hex_big(phex);
            vec.push(PrimeItem {
                bitlen: *bits,
                log2: log2_big(&v),
                hex: phex.to_string(),
                value: v,
            });
        }
    }
    vec
}

pub fn select_crt_primes_one_pack(limit_log2: f64, all: &[PrimeItem]) -> Vec<PrimeItem> {
    use std::collections::BTreeMap;

    // Group primes by bit-length, sort descending by value.
    let mut by_bits: BTreeMap<u8, Vec<PrimeItem>> = BTreeMap::new();
    for p in all {
        by_bits.entry(p.bitlen).or_default().push(p.clone());
    }
    for v in by_bits.values_mut() {
        v.sort_by(|a, b| b.value.cmp(&a.value));
    }

    let ceil_lim = limit_log2.ceil() as u64;

    let mut best_bb: Option<u8> = None;
    let mut best_target: u64 = u64::MAX; // store the overshoot multiple

    for bb in 40u8..=63u8 {
        if let Some(bucket) = by_bits.get(&bb) {
            if bucket.is_empty() {
                continue;
            }

            let bb_u = bb as u64;
            // next multiple of bb at or above ceil_lim
            let next_mult = ceil_lim.div_ceil(bb_u) * bb_u;

            if next_mult < ceil_lim {
                continue;
            } // should not happen
            let overshoot = next_mult - ceil_lim;

            // accept overshoot, but we want the smallest overshoot
            if overshoot < (best_target.saturating_sub(ceil_lim))
                || (overshoot == (best_target.saturating_sub(ceil_lim)) && Some(bb) > best_bb)
            {
                best_bb = Some(bb);
                best_target = next_mult;
            }
        }
    }

    if let Some(bb) = best_bb {
        let m = (best_target / bb as u64) as usize;
        return by_bits.get(&bb).unwrap().iter().take(m).cloned().collect();
    }

    Vec::new()
}

/// Try to select primes using ONLY one bit-size that best fits under limit_log2.
/// Returns Some(selection) if at least one prime of that size could be taken; otherwise None.
pub fn select_same_size_only(limit_log2: f64, all: &[PrimeItem]) -> Option<Vec<PrimeItem>> {
    let mut best: Option<(f64, Vec<PrimeItem>)> = None;

    for bit in (40u8..=63u8).rev() {
        let mut group: Vec<PrimeItem> = all.iter().filter(|pi| pi.bitlen == bit).cloned().collect();
        group.sort_by(|a, b| b.log2.partial_cmp(&a.log2).unwrap_or(Ordering::Equal));

        let mut sel: Vec<PrimeItem> = Vec::new();
        let mut sum = 0.0;
        for pi in group.iter() {
            if sum + pi.log2 <= limit_log2 + 1e-12 {
                sel.push(pi.clone());
                sum += pi.log2;
            }
        }
        if !sel.is_empty() {
            match &best {
                None => best = Some((sum, sel)),
                Some((best_sum, _)) => {
                    if sum > *best_sum + 1e-12 {
                        best = Some((sum, sel));
                    }
                }
            }
        }
    }

    best.map(|(_, v)| v)
}

/// Mixed-size greedy: start with the best single-size base (if any),
/// else from largest bit-size down, pack while respecting limit_log2.
pub fn select_mixed_size(
    limit_log2: f64,
    all: &[PrimeItem],
    base: Option<&[PrimeItem]>,
) -> Vec<PrimeItem> {
    let mut used: Vec<PrimeItem> = Vec::new();
    let mut sum = 0.0;

    if let Some(base_sel) = base {
        for pi in base_sel {
            if sum + pi.log2 <= limit_log2 + 1e-12 {
                used.push(pi.clone());
                sum += pi.log2;
            }
        }
    }

    for bit in (40u8..=63u8).rev() {
        let mut group: Vec<PrimeItem> = all.iter().filter(|pi| pi.bitlen == bit).cloned().collect();
        group.retain(|pi| !used.iter().any(|u| u.value == pi.value));
        group.sort_by(|a, b| b.log2.partial_cmp(&a.log2).unwrap_or(Ordering::Equal));

        for pi in group {
            if sum + pi.log2 <= limit_log2 + 1e-12 {
                sum += pi.log2;
                used.push(pi);
            }
        }
    }

    used
}

/// Top-level helper: first try same-size-only; if that yields at least one prime, prefer it.
/// If same-size-only yields nothing (limit too small), fall back to mixed-size greedy.
pub fn select_crt_primes(limit_log2: f64, all: &[PrimeItem]) -> Vec<PrimeItem> {
    if let Some(same_only) = select_same_size_only(limit_log2, all) {
        return same_only;
    }
    select_mixed_size(limit_log2, all, None)
}
