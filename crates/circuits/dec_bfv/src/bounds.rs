//! Bounds calculation for BFV decryption zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! and validation that input vectors stay within these bounds.

use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{Signed, ToPrimitive};
use shared::errors::{ZkFheError, ZkFheResult};
use std::sync::Arc;

/// Cryptographic parameters for BFV decryption circuit
#[derive(Clone, Debug)]
pub struct DecBfvCryptographicParameters {
    pub moduli: Vec<u64>,
    pub plaintext_modulus: u64,
    pub q_inverse_mod_t: u64,
    pub q_mod_t: BigUint,
    pub t_inv_mod_q: BigUint,
}

/// Bounds for BFV decryption circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct DecBfvBounds {
    /// Bound for secret key s
    pub s_bound: BigUint,
    /// Bounds for u_i polynomials (per-basis decryption results)
    pub u_i_bounds: Vec<BigUint>,
    /// Bound for global u polynomial
    pub u_global_bound: BigUint,
    /// Bounds for r_1 polynomials (modulus quotients)
    pub r1_bounds: Vec<BigUint>,
    /// Bounds for r_2 polynomials (cyclotomic quotients)
    pub r2_bounds: Vec<BigUint>,
    pub delta: BigInt,
    pub delta_half: BigInt,
}

impl DecBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(DecBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let t = BigInt::from(params.plaintext());
        let ctx = params.ctx_at_level(level)?;

        // Calculate delta = floor(q/t)
        let q = BigInt::from(ctx.modulus().clone());
        let delta = &q / &t;
        let delta_half = &delta / BigInt::from(2);

        // Secret key bound (ternary: {-1, 0, 1})
        let s_bound = SecretKey::sk_bound() as u128;

        // Calculate bounds for each CRT basis
        let mut u_i_bounds: Vec<BigInt> = Vec::new();
        let mut r1_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            // R2 bounds (cyclotomic quotients, same as qi_bound)
            r2_bounds.push(qi_bound.clone());

            // U_i bounds: these are the intermediate decryption results per CRT basis
            // u_i = c_0i + c_1i * s (before scaling)
            // Max coefficient: qi_bound + qi_bound * n * s_bound
            let u_i_bound = &qi_bound + &qi_bound * &n * s_bound;
            u_i_bounds.push(u_i_bound.clone());

            // R1 bounds (modulus quotients)
            // r_1_i = (c_0i + c_1i * s - u_i) / qi
            // This quotient arises from lifting the ring equation to integers
            // Bound: approximately u_i_bound / qi
            let r1_bound = (&u_i_bound + &qi_bound * &n * s_bound) / &qi_bigint;
            r1_bounds.push(r1_bound);
        }

        // U_global bound: after CRT reconstruction
        // u_global can be as large as Q (product of all moduli)
        // We use Q as the bound to be safe
        let u_global_bound: BigInt = q.clone();

        // Compute Q^{-1} mod t using extended Euclidean algorithm
        let q_inverse_mod_t = {
            let gcd_result = q.extended_gcd(&t);
            if gcd_result.gcd != BigInt::from(1) {
                return Err(ZkFheError::Bfv {
                    message: format!("Q and t are not coprime, gcd = {}", gcd_result.gcd),
                });
            }
            // Ensure the inverse is positive
            let inv = gcd_result.x % &t;
            let inv_positive = if inv < BigInt::from(0) { inv + &t } else { inv };
            inv_positive.to_u64().ok_or_else(|| ZkFheError::Bfv {
                message: format!("q_inverse_mod_t too large to fit in u64: {}", inv_positive),
            })?
        };

        // Compute q_mod_t: Q mod t
        let q_mod_t = {
            let q_biguint = q.to_biguint().ok_or_else(|| ZkFheError::Bfv {
                message: "Q is negative, cannot convert to BigUint".to_string(),
            })?;
            let t_biguint = t.to_biguint().ok_or_else(|| ZkFheError::Bfv {
                message: "t is negative, cannot convert to BigUint".to_string(),
            })?;
            &q_biguint % &t_biguint
        };

        // Compute t_inv_mod_q: t^(-1) mod Q
        let t_inv_mod_q = {
            let gcd_result = q.extended_gcd(&t);
            if gcd_result.gcd != BigInt::from(1) {
                return Err(ZkFheError::Bfv {
                    message: format!(
                        "Q and t are not coprime (gcd = {}), cannot compute modular inverse",
                        gcd_result.gcd
                    ),
                });
            }
            // y is t^(-1) mod Q (from the extended GCD: Q*x + t*y = gcd)
            // But may be negative, so normalize to [0, Q)
            let t_inverse_bigint = if gcd_result.y < BigInt::from(0) {
                gcd_result.y + &q
            } else {
                gcd_result.y
            };
            t_inverse_bigint
                .to_biguint()
                .ok_or_else(|| ZkFheError::Bfv {
                    message: "Failed to convert t_inv_mod_q to BigUint".to_string(),
                })?
        };

        let crypto_params = DecBfvCryptographicParameters {
            moduli: ctx.moduli().to_vec(),
            plaintext_modulus: params.plaintext(),
            q_inverse_mod_t,
            q_mod_t,
            t_inv_mod_q,
        };

        let bounds = DecBfvBounds {
            s_bound: BigUint::from(s_bound),
            u_i_bounds: u_i_bounds
                .iter()
                .map(|b| BigUint::from(b.abs().to_u128().unwrap_or(u128::MAX)))
                .collect(),
            u_global_bound: BigUint::from(u_global_bound.abs().to_u128().unwrap_or(u128::MAX)),
            r1_bounds: r1_bounds
                .iter()
                .map(|b| BigUint::from(b.abs().to_u128().unwrap_or(u128::MAX)))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            delta,
            delta_half,
        };

        Ok((crypto_params, bounds))
    }
}

impl DecBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli,
            "plaintext_modulus": self.plaintext_modulus,
            "q_inverse_mod_t": self.q_inverse_mod_t,
            "q_mod_t": self.q_mod_t.to_string(),
            "t_inv_mod_q": self.t_inv_mod_q.to_string(),
        })
    }
}

impl DecBfvBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "s_bound": self.s_bound,
            "u_i_bounds": self.u_i_bounds,
            "u_global_bound": self.u_global_bound,
            "r1_bounds": self.r1_bounds,
            "r2_bounds": self.r2_bounds,
            "delta": self.delta.to_string(),
            "delta_half": self.delta_half.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters;

    #[test]
    fn test_bounds_computation() {
        let params = test_parameters();
        let (crypto_params, bounds) = DecBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), params.moduli().len());
        assert_eq!(bounds.u_i_bounds.len(), params.moduli().len());
        assert_eq!(bounds.r1_bounds.len(), params.moduli().len());
        assert_eq!(bounds.r2_bounds.len(), params.moduli().len());
        assert!(bounds.delta > BigInt::from(0u32));
        assert!(bounds.delta_half > BigInt::from(0u32));

        // Verify bounds are positive
        assert!(bounds.s_bound > BigUint::from(0u32));
        assert!(bounds.u_global_bound > BigUint::from(0u32));
    }
}
