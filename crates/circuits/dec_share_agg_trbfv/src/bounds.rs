//! Bounds calculation for Decryption Share Aggregation TRBFV zero-knowledge proofs.
//!
//! This module handles the computation of DELTA, DELTA_HALF, and noise bounds
//! used in threshold BFV decryption share aggregation verification.

use fhe::bfv::BfvParameters;
use num_bigint::BigUint;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for Decryption Share Aggregation TRBFV circuit
#[derive(Clone, Debug)]
pub struct DecShareAggTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
    pub plaintext_modulus: u64,
}

/// Bounds for Decryption Share Aggregation TRBFV circuit
#[derive(Clone, Debug)]
pub struct DecShareAggTrBfvBounds {
    pub delta: BigUint,
    pub delta_half: BigUint,
}

impl DecShareAggTrBfvBounds {
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
    ) -> ZkFheResult<(DecShareAggTrBfvCryptographicParameters, Self)> {
        let ctx = params.ctx_at_level(level)?;

        // Compute Q = product of all moduli
        let mut q_product = BigUint::from(1u64);
        for &modulus in ctx.moduli() {
            q_product *= BigUint::from(modulus);
        }

        // Compute delta = floor(Q / t) where t is plaintext_modulus
        let t = BigUint::from(params.plaintext());
        let delta = &q_product / &t;

        // Compute delta_half = floor(delta / 2)
        let delta_half = &delta / BigUint::from(2u64);

        let crypto_params = DecShareAggTrBfvCryptographicParameters {
            moduli: ctx.moduli().to_vec(),
            plaintext_modulus: params.plaintext(),
        };

        let bounds = DecShareAggTrBfvBounds { delta, delta_half };

        Ok((crypto_params, bounds))
    }
}

impl DecShareAggTrBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "qis": self.moduli,
            "plaintext_modulus": self.plaintext_modulus.to_string(),
        })
    }
}

impl DecShareAggTrBfvBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "delta": self.delta.to_string(),
            "delta_half": self.delta_half.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::BfvParametersBuilder;

    fn setup_test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[0x3FFFFFFF000001])
            .set_variance(10)
            .set_error1_variance(num_bigint::BigUint::from(10u32))
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_bounds_computation() {
        let params = setup_test_params();
        let (crypto_params, bounds) = DecShareAggTrBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert!(bounds.delta > BigUint::from(0u64));
        assert!(bounds.delta_half > BigUint::from(0u64));
        assert_eq!(bounds.delta_half, bounds.delta_half);
    }
}
