//! Constants
//!
//! This module contains constants that are shared,
//! such as ZKP moduli and other cryptographic constants.

use num_bigint::BigInt;
use std::str::FromStr;

/// ZKP modulus (BN254 scalar field)
pub const ZKP_MODULUS: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

/// Get the ZKP modulus as a BigInt
pub fn get_zkp_modulus() -> BigInt {
    BigInt::from_str(ZKP_MODULUS).expect("Invalid ZKP modulus")
}

/// Default secure security parameter (λ)
///
/// Parameters with lambda >= 80 are considered secure.
/// This is the recommended value for production use.
pub const DEFAULT_SECURE_LAMBDA: usize = 80;

/// Default insecure security parameter (λ) for testing/development
///
/// Parameters with lambda < 80 are considered insecure.
/// This value is used for testing and development purposes only.
pub const DEFAULT_INSECURE_LAMBDA: usize = 2;
