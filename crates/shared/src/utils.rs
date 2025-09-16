//! Utility functions for zkFHE circuit generation
//!
//! This module contains helper functions for string conversion,
//! serialization, and other common operations.

use bigint_poly::reduce_and_center_coefficients;
use num_bigint::BigInt;

/// Convert a 1D vector of BigInt to a vector of strings
pub fn to_string_1d_vec(vec: &[BigInt]) -> Vec<String> {
    vec.iter().map(|x| x.to_string()).collect()
}

/// Convert a 2D vector of BigInt to a vector of vectors of strings
pub fn to_string_2d_vec(poly: &[Vec<BigInt>]) -> Vec<Vec<String>> {
    poly.iter().map(|row| to_string_1d_vec(row)).collect()
}

/// Convert a 3D vector of BigInt to a vector of vectors of vectors of strings
pub fn to_string_3d_vec(poly: &[Vec<Vec<BigInt>>]) -> Vec<Vec<Vec<String>>> {
    poly.iter().map(|matrix| to_string_2d_vec(matrix)).collect()
}

/// Convert a 4D vector of BigInt to a vector of vectors of vectors of vectors of strings
pub fn to_string_4d_vec(poly: &[Vec<Vec<Vec<BigInt>>>]) -> Vec<Vec<Vec<Vec<String>>>> {
    poly.iter()
        .map(|matrix_3d| to_string_3d_vec(matrix_3d))
        .collect()
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

/// Reduce coefficients of a 3D vector modulo the given modulus
pub fn reduce_coefficients_3d(vec: &[Vec<Vec<BigInt>>], modulus: &BigInt) -> Vec<Vec<Vec<BigInt>>> {
    vec.iter()
        .map(|matrix| reduce_coefficients_2d(matrix, modulus))
        .collect()
}

/// Reduce coefficients of a 4D vector modulo the given modulus
pub fn reduce_coefficients_4d(
    vec: &[Vec<Vec<Vec<BigInt>>>],
    modulus: &BigInt,
) -> Vec<Vec<Vec<Vec<BigInt>>>> {
    vec.iter()
        .map(|matrix_3d| reduce_coefficients_3d(matrix_3d, modulus))
        .collect()
}
