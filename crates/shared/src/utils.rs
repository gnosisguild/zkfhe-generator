//! Utility functions for zkFHE circuit generation
//!
//! This module contains helper functions for string conversion,
//! serialization, and other common operations.

use bigint_poly::reduce_and_center_coefficients;
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

/// Reduce coefficients of a 1D vector modulo the given modulus
pub fn reduce_coefficients(vec: &[BigInt], modulus: &BigInt) -> Vec<BigInt> {
    let result = vec.to_vec();
    reduce_and_center_coefficients(&result, modulus);
    result
}

/// Reduce coefficients of a 2D vector modulo the given modulus
pub fn reduce_coefficients_2d(vec: &[Vec<BigInt>], modulus: &BigInt) -> Vec<Vec<BigInt>> {
    vec.iter()
        .map(|row| reduce_coefficients(row, modulus))
        .collect()
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
