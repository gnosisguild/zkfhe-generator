//! Utility functions for zkFHE circuit generation
//!
//! This module contains helper functions for string conversion,
//! serialization, and other common operations.

use fhe::bfv::BfvParameters;
use fhe::bfv::BfvParametersBuilder;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::Zero;
use std::sync::Arc;

/// Convert a 1D vector of BigInt to a vector of strings
pub fn to_string_1d_vec(vec: &[BigInt]) -> Vec<String> {
    vec.iter().map(|x| x.to_string()).collect()
}

/// Convert a 2D vector of BigInt to a vector of vectors of strings
pub fn to_string_2d_vec(poly: &[Vec<BigInt>]) -> Vec<Vec<String>> {
    poly.iter().map(|row| to_string_1d_vec(row)).collect()
}

/// Convert a 3D vector of BigInt to a vector of vectors of vectors of strings
pub fn to_string_3d_vec(vec: &[Vec<Vec<BigInt>>]) -> Vec<Vec<Vec<String>>> {
    vec.iter().map(|d1| to_string_2d_vec(d1)).collect()
}

/// Convert a 4D vector of BigInt to a vector of vectors of vectors of vectors of strings
pub fn to_string_4d_vec(vec: &[Vec<Vec<Vec<BigInt>>>]) -> Vec<Vec<Vec<Vec<String>>>> {
    vec.iter().map(|d1| to_string_3d_vec(d1)).collect()
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

pub fn test_parameters_trbfv() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(512)
        .set_plaintext_modulus(10)
        .set_moduli(&[0xffffee001, 0xffffc4001])
        .set_variance(10)
        .set_error1_variance(BigUint::from(3u32))
        .build_arc()
        .unwrap()
}

pub fn test_parameters_bfv() -> Arc<BfvParameters> {
    BfvParametersBuilder::new()
        .set_degree(512)
        .set_plaintext_modulus(0xffffee001)
        .set_moduli(&[0x7fffffffe0001])
        .set_variance(3)
        .build_arc()
        .unwrap()
}
