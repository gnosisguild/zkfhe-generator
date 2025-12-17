//! Bounds calculation for Secret Key Shares verification zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for secret key coefficients
//! and share values used in the Reed-Solomon parity check verification.

use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::BigUint;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for Verify Shares TRBFV circuit
#[derive(Clone, Debug)]
pub struct VerifySharesTrbfvCryptographicParameters {
    pub moduli: Vec<u64>,
    pub plaintext_modulus: u64,
}

/// Bounds for Verify Shares TRBFV circuit
#[derive(Clone, Debug)]
pub struct VerifySharesTrbfvBounds {
    /// Bound for secret key coefficients (trinary: {-1, 0, 1})
    pub sk_bound: BigUint,
}

impl VerifySharesTrbfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `level` - The CRT level to compute bounds for
    ///
    /// # Returns
    /// A tuple of (cryptographic parameters, bounds)
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(VerifySharesTrbfvCryptographicParameters, Self)> {
        let ctx = params.ctx_at_level(level)?;

        // Secret key bound (trinary: {-1, 0, 1})
        let sk_bound = SecretKey::sk_bound() as u128;

        let crypto_params = VerifySharesTrbfvCryptographicParameters {
            moduli: ctx.moduli().to_vec(),
            plaintext_modulus: params.plaintext(),
        };

        let bounds = VerifySharesTrbfvBounds {
            sk_bound: BigUint::from(sk_bound),
        };

        Ok((crypto_params, bounds))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_bfv;

    #[test]
    fn test_bounds_computation() {
        let params = test_parameters_bfv();
        let (crypto_params, bounds) = VerifySharesTrbfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), params.moduli().len());

        // Verify sk_bound is 1 (trinary)
        assert_eq!(bounds.sk_bound, BigUint::from(1u64));
    }
}
