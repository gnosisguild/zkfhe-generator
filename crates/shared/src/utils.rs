//! Utility functions for zkFHE circuit generation
//!
//! This module contains helper functions for string conversion,
//! serialization, and other common operations.

use bigint_poly::{Polynomial, reduce_and_center_coefficients, reduce_scalar};
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

// Helper function to convert a polynomial (Vec<BigInt>) to a Polynomial
pub fn poly_to_coeff_obj(poly: &[num_bigint::BigInt]) -> Polynomial {
    Polynomial::new(poly.to_vec())
}

// Helper function to convert a 2D matrix to the correct format
pub fn matrix_to_format(matrix: &[Vec<Vec<num_bigint::BigInt>>]) -> Vec<Vec<serde_json::Value>> {
    matrix
        .iter()
        .map(|row| {
            row.iter()
                .map(|poly| serde_json::to_value(poly_to_coeff_obj(poly)).unwrap())
                .collect()
        })
        .collect()
}

// Helper function to convert a 3D matrix to the correct format
pub fn matrix_3d_to_format(
    matrix_3d: &[Vec<Vec<Vec<num_bigint::BigInt>>>],
) -> Vec<Vec<Vec<serde_json::Value>>> {
    matrix_3d
        .iter()
        .map(|matrix| matrix_to_format(matrix))
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

// Helper functions to reduce coefficients using reduce_scalar for Noir compatibility
pub fn reduce_1d(vec: &[BigInt], modulus: &BigInt) -> Vec<BigInt> {
    vec.iter().map(|x| reduce_scalar(x, modulus)).collect()
}

pub fn reduce_2d(vec: &[Vec<BigInt>], modulus: &BigInt) -> Vec<Vec<BigInt>> {
    vec.iter().map(|row| reduce_1d(row, modulus)).collect()
}

pub fn reduce_3d(vec: &[Vec<Vec<BigInt>>], modulus: &BigInt) -> Vec<Vec<Vec<BigInt>>> {
    vec.iter()
        .map(|matrix| reduce_2d(matrix, modulus))
        .collect()
}

pub fn reduce_4d(vec: &[Vec<Vec<Vec<BigInt>>>], modulus: &BigInt) -> Vec<Vec<Vec<Vec<BigInt>>>> {
    vec.iter()
        .map(|matrix_3d| reduce_3d(matrix_3d, modulus))
        .collect()
}
