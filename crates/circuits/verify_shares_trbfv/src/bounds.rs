//! Bounds calculation for Secret Key Shares verification zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for secret key coefficients
//! and share values used in the Reed-Solomon parity check verification.

use fhe::bfv::{BfvParameters, SecretKey};
use fhe::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use num_bigint::BigUint;
use shared::circuit::CiphernodesConfig;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for Verify Shares TRBFV circuit
#[derive(Clone, Debug)]
pub struct VerifySharesTrbfvCryptographicParameters {
    pub moduli: Vec<u64>,
}

/// Bounds for Verify Shares TRBFV circuit
#[derive(Clone, Debug)]
pub struct VerifySharesTrbfvBounds {
    /// Bound for secret key coefficients (trinary: {-1, 0, 1})
    pub sk_bound: BigUint,
    /// Bound for smudging noise coefficients (when using SmudgingNoise sample type)
    pub e_sm_bound: Option<BigUint>,
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
        };

        let bounds = VerifySharesTrbfvBounds {
            sk_bound: BigUint::from(sk_bound),
            e_sm_bound: None, // Will be calculated when needed based on sample_type
        };

        Ok((crypto_params, bounds))
    }

    /// Compute bounds including smudging noise bound
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `level` - The CRT level to compute bounds for
    /// * `lambda` - Security parameter for smudging noise bound calculation
    /// * `ciphernodes_config` - Configuration with num_parties and threshold
    /// * `num_ciphertexts` - Number of ciphertexts being processed
    ///
    /// # Returns
    /// A tuple of (cryptographic parameters, bounds)
    pub fn compute_with_smudging(
        params: &Arc<BfvParameters>,
        level: usize,
        lambda: usize,
        ciphernodes_config: &CiphernodesConfig,
        num_ciphertexts: usize,
    ) -> ZkFheResult<(VerifySharesTrbfvCryptographicParameters, Self)> {
        let ctx = params.ctx_at_level(level)?;

        // Secret key bound (trinary: {-1, 0, 1})
        let sk_bound = SecretKey::sk_bound() as u128;

        // Calculate smudging noise bound using SmudgingBoundCalculator from fhe.rs
        let smudging_config = SmudgingBoundCalculatorConfig::new(
            params.clone(),
            ciphernodes_config.num_parties,
            num_ciphertexts,
            lambda,
        );
        let smudging_calculator = SmudgingBoundCalculator::new(smudging_config);
        let e_sm_bound = smudging_calculator.calculate_sm_bound().map_err(|e| {
            shared::errors::ZkFheError::Bfv {
                message: format!("Failed to calculate smudging bound: {:?}", e),
            }
        })?;

        let crypto_params = VerifySharesTrbfvCryptographicParameters {
            moduli: ctx.moduli().to_vec(),
        };

        let bounds = VerifySharesTrbfvBounds {
            sk_bound: BigUint::from(sk_bound),
            e_sm_bound: Some(e_sm_bound),
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
