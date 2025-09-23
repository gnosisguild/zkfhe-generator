use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::cmp::Ordering;

pub fn parse_hex_big(s: &str) -> BigUint {
    let t = s.trim_start_matches("0x");
    BigUint::parse_bytes(t.as_bytes(), 16).expect("invalid hex prime")
}

pub fn product(xs: &[BigUint]) -> BigUint {
    let mut acc = BigUint::one();
    for x in xs {
        acc *= x;
    }
    acc
}

pub fn log2_big(x: &BigUint) -> f64 {
    if x.is_zero() {
        return f64::NEG_INFINITY;
    }
    let bytes = x.to_bytes_be();
    let leading = bytes[0];
    let lead_bits = 8 - leading.leading_zeros() as usize;
    let bits = (bytes.len() - 1) * 8 + lead_bits;

    // refine with up to 8 bytes
    let take = bytes.len().min(8);
    let mut top: u64 = 0;
    for &byte in bytes.iter().take(take) {
        top = (top << 8) | byte as u64;
    }
    let frac = (top as f64).log2();
    let adjust = (take * 8) as f64;
    (bits as f64 - adjust) + frac
}

pub fn approx_bits_from_log2(log2x: f64) -> u64 {
    if log2x <= 0.0 {
        1
    } else {
        log2x.floor() as u64 + 1
    }
}

pub fn fmt_big_summary(x: &BigUint) -> String {
    let bits = approx_bits_from_log2(log2_big(x));
    format!("≈ 2^{bits} ({bits} bits)")
}

pub fn big_shift_pow2(exp: u32) -> BigUint {
    BigUint::one() << exp
}

/// Exact variance string for Uniform(-B..B): Var = B(B+1)/3 (exact)
pub fn variance_uniform_sym_str_u128(b: u128) -> String {
    let num = b.checked_mul(b + 1).expect("overflow in B(B+1)");
    if num % 3 == 0 {
        (num / 3).to_string()
    } else {
        format!("{num}/3")
    }
}

pub fn variance_uniform_sym_str_big(b: &BigUint) -> String {
    let three = BigUint::from(3u32);
    let num = b * (b + BigUint::from(1u32));
    if (&num % &three).is_zero() {
        (num / three).to_str_radix(10)
    } else {
        format!("{}/3", num.to_str_radix(10))
    }
}

pub fn cap_ok_log2(x: &BigUint, limit_log2: f64) -> bool {
    log2_big(x) <= limit_log2 + 1.0 + 1e-12
}

pub fn comb_indices(n: usize, k: usize, res: &mut Vec<Vec<usize>>) {
    fn rec(start: usize, n: usize, k: usize, cur: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
        if cur.len() == k {
            out.push(cur.clone());
            return;
        }
        let need = k - cur.len();
        for i in start..=n - need {
            cur.push(i);
            rec(i + 1, n, k, cur, out);
            cur.pop();
        }
    }
    res.clear();
    rec(0, n, k, &mut Vec::new(), res);
}

pub fn sum_bits_exact(sel: &[&BigUint]) -> f64 {
    let mut acc = BigUint::one();
    for v in sel {
        acc *= *v;
    }
    log2_big(&acc)
}

pub fn big_pow(base: &BigUint, exp: u64) -> BigUint {
    let mut res = BigUint::one();
    for _ in 0..exp {
        res *= base;
    }
    res
}

pub fn nth_root_floor(a: &BigUint, n: u32) -> BigUint {
    if n <= 1 {
        return a.clone();
    }
    if a.is_zero() {
        return BigUint::zero();
    }
    let bits: usize = a.bits() as usize;
    let n_usize: usize = n as usize;
    let ub = BigUint::one() << bits.div_ceil(n_usize);
    let mut lo = BigUint::one();
    let mut hi = ub;
    while lo < hi {
        let mid = (&lo + &hi + BigUint::one()) >> 1;
        let mid_pow = big_pow(&mid, n as u64);
        match mid_pow.cmp(a) {
            Ordering::Less | Ordering::Equal => lo = mid,
            Ordering::Greater => hi = mid - BigUint::one(),
        }
    }
    lo
}
