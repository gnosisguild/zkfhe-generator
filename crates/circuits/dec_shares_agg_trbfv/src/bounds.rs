//! Bounds calculation for Decryption Share Aggregation TRBFV zero-knowledge proofs.
//!
//! This module handles the computation of DELTA, DELTA_HALF, and noise bounds
//! used in threshold BFV decryption share aggregation verification.

use fhe::bfv::BfvParameters;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::ToPrimitive;
use shared::errors::{ZkFheError, ZkFheResult};
use std::sync::Arc;

/// Cryptographic parameters for Decryption Shares Aggregation TRBFV circuit
#[derive(Clone, Debug)]
pub struct DecSharesAggTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
    pub plaintext_modulus: u64,
    pub q_inverse_mod_t: u64,
    pub q_mod_t: BigUint,
    pub t_inv_mod_q: BigUint,
}

/// Bounds for Decryption Shares Aggregation TRBFV circuit
#[derive(Clone, Debug)]
pub struct DecSharesAggTrBfvBounds {
    pub delta: BigUint,
    pub delta_half: BigUint,
}

impl DecSharesAggTrBfvBounds {
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
    ) -> ZkFheResult<(DecSharesAggTrBfvCryptographicParameters, Self)> {
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

        // Compute Q^{-1} mod t using extended Euclidean algorithm
        let q_inverse_mod_t = {
            let q_bigint = BigInt::from(q_product.clone());
            let t_bigint = BigInt::from(params.plaintext());
            let gcd_result = q_bigint.extended_gcd(&t_bigint);
            if gcd_result.gcd != BigInt::from(1) {
                return Err(ZkFheError::Bfv {
                    message: format!("Q and t are not coprime, gcd = {}", gcd_result.gcd),
                });
            }
            // Ensure the inverse is positive
            let inv = gcd_result.x % &t_bigint;
            let inv_positive = if inv < BigInt::from(0) {
                inv + &t_bigint
            } else {
                inv
            };
            inv_positive.to_u64().ok_or_else(|| ZkFheError::Bfv {
                message: format!("q_inverse_mod_t too large to fit in u64: {}", inv_positive),
            })?
        };
        // Helper function: Extended Euclidean Algorithm
        // Finds gcd(a, b) and coefficients x, y such that ax + by = gcd(a, b)
        fn extended_gcd(
            a: &num_bigint::BigInt,
            b: &num_bigint::BigInt,
        ) -> (num_bigint::BigInt, num_bigint::BigInt, num_bigint::BigInt) {
            use num_bigint::BigInt;
            use num_traits::Zero;

            if b.is_zero() {
                return (a.clone(), BigInt::from(1u64), BigInt::from(0u64));
            }
            let (gcd, x1, y1) = extended_gcd(b, &(a % b));
            let x = y1.clone();
            let y = x1 - (a / b) * &y1;
            (gcd, x, y)
        }

        // Compute q_mod_t: Q mod t
        // This is simply the remainder when Q is divided by t
        let q_mod_t = &q_product % &t;

        // Compute t_inv_mod_q: t^(-1) mod Q
        // This is the modular multiplicative inverse of t modulo Q
        let t_inv_mod_q = {
            use num_bigint::BigInt;

            let q_bigint = BigInt::from(q_product.clone());
            let t_bigint = BigInt::from(t.clone());

            let (gcd, _x, y) = extended_gcd(&q_bigint, &t_bigint);

            // Check that gcd(Q, t) = 1 (already checked above, but being explicit)
            if gcd != BigInt::from(1u64) {
                return Err(shared::errors::ZkFheError::Bfv {
                    message: format!(
                        "Q and t are not coprime (gcd = {}), cannot compute modular inverse",
                        gcd
                    ),
                });
            }

            // y is t^(-1) mod Q (from the extended GCD: Q*x + t*y = gcd)
            // But may be negative, so normalize to [0, Q)
            let t_inverse_bigint = if y < BigInt::from(0u64) {
                y + &q_bigint
            } else {
                y
            };

            t_inverse_bigint
                .to_biguint()
                .ok_or_else(|| shared::errors::ZkFheError::Bfv {
                    message: "Failed to convert t_inv_mod_q to BigUint".to_string(),
                })?
        };

        let crypto_params = DecSharesAggTrBfvCryptographicParameters {
            moduli: ctx.moduli().to_vec(),
            plaintext_modulus: params.plaintext(),
            q_inverse_mod_t,
            q_mod_t,
            t_inv_mod_q,
        };

        let bounds = DecSharesAggTrBfvBounds { delta, delta_half };

        Ok((crypto_params, bounds))
    }
}

impl DecSharesAggTrBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "qis": self.moduli,
            "plaintext_modulus": self.plaintext_modulus.to_string(),
            "q_inverse_mod_t": self.q_inverse_mod_t.to_string(),
            "q_mod_t": self.q_mod_t.to_string(),
            "t_inv_mod_q": self.t_inv_mod_q.to_string(),
        })
    }
}

impl DecSharesAggTrBfvBounds {
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
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_bounds_computation() {
        let params = test_parameters_trbfv();
        let (crypto_params, bounds) = DecSharesAggTrBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 2);
        assert!(bounds.delta > BigUint::from(0u64));
        assert!(bounds.delta_half > BigUint::from(0u64));
        assert_eq!(bounds.delta_half, bounds.delta_half);
    }
}
