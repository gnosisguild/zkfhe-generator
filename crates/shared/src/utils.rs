//! Utility functions for zkFHE circuit generation
//!
//! This module contains helper functions for string conversion,
//! serialization, and other common operations.

use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::Zero;

/// Convert a 1D vector of BigInt to a vector of strings
pub fn to_string_1d_vec(vec: &[BigInt]) -> Vec<String> {
    vec.iter().map(|x| x.to_string()).collect()
}

/// Convert a 2D vector of BigInt to a vector of vectors of strings
pub fn to_string_2d_vec(poly: &[Vec<BigInt>]) -> Vec<Vec<String>> {
    poly.iter().map(|row| to_string_1d_vec(row)).collect()
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
