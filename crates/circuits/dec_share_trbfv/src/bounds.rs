//! Bounds calculation for Decryption Share TRBFV zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! used in threshold BFV decryption share correctness verification.
//!
//! Based on the mathematical analysis:
//! - d_j = c_0j + c_1j * s + e + r_2j * (X^N + 1) + r_1j * q_j (mod Z)
//! - Where s = Σy_i (aggregated shares) and e = Σe_i (aggregated noise)

use fhe::bfv::BfvParameters;
use num_bigint::{BigInt, BigUint};
use num_traits::ToPrimitive;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for Decryption Share TRBFV circuit
#[derive(Clone, Debug)]
pub struct DecShareTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
}

/// Bounds for Decryption Share TRBFV circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct DecShareTrBfvBounds {
    /// Bound for computed decryption share d (maximum across all moduli)
    pub decryption_share_bound: BigUint,
    /// Bounds for r_1 polynomials (modulus quotients)
    pub r1_bounds: Vec<BigUint>,
    /// Bounds for r_2 polynomials (cyclotomic quotients)
    pub r2_bounds: Vec<BigUint>,
}

impl DecShareTrBfvBounds {
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
    ) -> ZkFheResult<(DecShareTrBfvCryptographicParameters, Self)> {
        let n = BigInt::from(params.degree());
        // Get cyclotomic degree and context at provided level
        let ctx = params.ctx_at_level(level)?;

        // Calculate bounds for each CRT basis
        let mut decryption_share_bound_max = BigInt::from(0);
        let mut r1_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();
        let mut moduli: Vec<u64> = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            moduli.push(qi.modulus());

            // Decryption share d_j bounds: [- (q_j-1)/2 , (q_j-1)/2]
            // Track the maximum bound across all moduli
            if qi_bound > decryption_share_bound_max {
                decryption_share_bound_max = qi_bound.clone();
            }

            // r_2j bounds: [- (q_j-1)/2 , (q_j-1)/2] (cyclotomic quotients)
            r2_bounds.push(qi_bound.clone());

            // r_1j bounds: based on the formula from the notes
            // r_1j: [(-(q_j-1)/2 * (BS.N+3) - Be) / q_j , ((q_j-1)/2 * (BS.N+3) + Be) / q_j]
            // Where BS = s_bound, Be = e_bound, N = n (degree)
            r1_bounds.push(
                (&qi_bound * (&qi_bound.clone() * &n + BigInt::from(3)) - &qi_bound.clone())
                    / &qi_bigint,
            );
        }

        let crypto_params = DecShareTrBfvCryptographicParameters { moduli };

        let bounds = DecShareTrBfvBounds {
            decryption_share_bound: BigUint::from(decryption_share_bound_max.to_u128().unwrap()),
            r1_bounds: r1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        };

        Ok((crypto_params, bounds))
    }
}

impl DecShareTrBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli,
        })
    }
}

impl DecShareTrBfvBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "decryption_share_bound": self.decryption_share_bound,
            "r1_bounds": self.r1_bounds,
            "r2_bounds": self.r2_bounds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::BfvParametersBuilder;
    use num_bigint::BigUint;

    fn setup_test_params() -> Arc<BfvParameters> {
        BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[0x3FFFFFFF000001])
            .set_variance(10)
            .set_error2_variance(BigUint::from(10u32))
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_bounds_computation() {
        let params = setup_test_params();
        let (crypto_params, bounds) = DecShareTrBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert_eq!(bounds.r1_bounds.len(), 1);
        assert_eq!(bounds.r2_bounds.len(), 1);
    }
}
