//! Bounds calculation for BFV decryption (no homomorphic addition) zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! and validation that input vectors stay within these bounds.
//!
//! Key parameters:
//! - L: Number of TRBFV CRT moduli (number of ciphertexts per party)
//! - L': Number of BFV CRT moduli (for decryption)
//! - H: Number of honest parties

use fhe::bfv::{BfvParameters, SecretKey};
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{Signed, ToPrimitive};
use shared::errors::{ZkFheError, ZkFheResult};
use std::sync::Arc;

/// Cryptographic parameters for BFV decryption circuit (no homomorphic addition)
#[derive(Clone, Debug)]
pub struct DecBfvNoHomAddCryptographicParameters {
    /// BFV CRT moduli: [q'_0, q'_1, ..., q'_{L'-1}]
    pub bfv_moduli: Vec<u64>,
    /// BFV plaintext modulus (large enough for TRBFV values)
    pub bfv_plaintext_modulus: u64,
    /// BFV Q^{-1} mod t for decoding
    pub bfv_q_inverse_mod_t: u64,
    /// TRBFV CRT moduli: [q_0, q_1, ..., q_{L-1}]
    pub trbfv_moduli: Vec<u64>,
}

/// Bounds for BFV decryption circuit polynomial coefficients (no homomorphic addition)
#[derive(Clone, Debug)]
pub struct DecBfvNoHomAddBounds {
    /// Bound for BFV secret key s
    pub s_bound: BigUint,
    /// Bounds for u_i polynomials (per BFV basis)
    pub u_i_bounds: Vec<BigUint>,
    /// Bound for global u polynomial
    pub u_global_bound: BigUint,
    /// Bounds for r_1 polynomials (modulus quotients, per BFV basis)
    pub r1_bounds: Vec<BigUint>,
    /// Bounds for r_2 polynomials (cyclotomic quotients, per BFV basis)
    pub r2_bounds: Vec<BigUint>,
    /// Delta = floor(Q'/t) where Q' is product of BFV moduli
    pub delta: BigInt,
    /// Delta half = floor(delta/2)
    pub delta_half: BigInt,
}

impl DecBfvNoHomAddBounds {
    /// Compute bounds and cryptographic parameters from BFV and TRBFV parameters
    ///
    /// # Arguments
    /// * `bfv_params` - BFV parameters for share encryption/decryption
    /// * `trbfv_params` - TRBFV parameters (provides the moduli for aggregation)
    /// * `level` - The level at which to compute bounds
    pub fn compute(
        bfv_params: &Arc<BfvParameters>,
        trbfv_params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(DecBfvNoHomAddCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(bfv_params.degree());
        let t = BigInt::from(bfv_params.plaintext());
        let ctx = bfv_params.ctx_at_level(level)?;

        // Calculate delta = floor(Q'/t) where Q' is product of BFV moduli
        let q = BigInt::from(ctx.modulus().clone());
        let delta = &q / &t;
        let delta_half = &delta / BigInt::from(2);

        // Secret key bound (ternary: {-1, 0, 1})
        let s_bound = SecretKey::sk_bound() as u128;

        // Calculate bounds for each BFV CRT basis
        let mut u_i_bounds: Vec<BigInt> = Vec::new();
        let mut r1_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            // R2 bounds (cyclotomic quotients, same as qi_bound)
            r2_bounds.push(qi_bound.clone());

            // U_i bounds: these are the intermediate decryption results per BFV CRT basis
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
        // u_global can be as large as Q (product of all BFV moduli)
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

        let crypto_params = DecBfvNoHomAddCryptographicParameters {
            bfv_moduli: ctx.moduli().to_vec(),
            bfv_plaintext_modulus: bfv_params.plaintext(),
            bfv_q_inverse_mod_t: q_inverse_mod_t,
            trbfv_moduli: trbfv_params.moduli().to_vec(),
        };

        let bounds = DecBfvNoHomAddBounds {
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

impl DecBfvNoHomAddCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "bfv_moduli": self.bfv_moduli,
            "bfv_plaintext_modulus": self.bfv_plaintext_modulus,
            "bfv_q_inverse_mod_t": self.bfv_q_inverse_mod_t,
            "trbfv_moduli": self.trbfv_moduli,
        })
    }
}

impl DecBfvNoHomAddBounds {
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
    use shared::utils::{test_parameters_bfv, test_parameters_trbfv};

    #[test]
    fn test_bounds_computation() {
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();
        let (crypto_params, bounds) =
            DecBfvNoHomAddBounds::compute(&bfv_params, &trbfv_params, 0).unwrap();

        assert_eq!(crypto_params.bfv_moduli.len(), bfv_params.moduli().len());
        assert_eq!(bounds.u_i_bounds.len(), bfv_params.moduli().len());
        assert_eq!(bounds.r1_bounds.len(), bfv_params.moduli().len());
        assert_eq!(bounds.r2_bounds.len(), bfv_params.moduli().len());
        assert!(bounds.delta > BigInt::from(0u32));
        assert!(bounds.delta_half > BigInt::from(0u32));

        // Verify bounds are positive
        assert!(bounds.s_bound > BigUint::from(0u32));
        assert!(bounds.u_global_bound > BigUint::from(0u32));
    }
}
