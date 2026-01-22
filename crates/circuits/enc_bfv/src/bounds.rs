//! Bounds calculation for BFV Encryption zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! and validation that input vectors stay within these bounds.

use fhe::bfv::BfvParameters;
use fhe::bfv::SecretKey;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_bigint::ToBigInt;
use num_traits::{Signed, ToPrimitive};
use polynomial::{reduce_and_center_scalar, reduce_scalar};
use shared::constants::get_zkp_modulus;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for BFV Encryption circuit
#[derive(Clone, Debug)]
pub struct EncBfvCryptographicParameters {
    pub t: u64,
    pub q_mod_t: BigInt,
    pub moduli: Vec<u64>,
    pub k0is: Vec<u64>,
}

/// Bounds for BFV Encryption circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct EncBfvBounds {
    // Bounds for different polynomial types
    pub u_bound: BigUint,
    pub e0_bound: BigUint,
    pub e1_bound: BigUint,
    pub msg_bound: BigUint,
    pub pk_bounds: Vec<BigUint>,
    pub r1_low_bounds: Vec<BigUint>,
    pub r1_up_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
    pub p1_bounds: Vec<BigUint>,
    pub p2_bounds: Vec<BigUint>,
}

impl EncBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(EncBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let t = BigInt::from(params.plaintext());
        let ctx = params.ctx_at_level(level)?;

        // Calculate q mod t
        let q_mod_t = reduce_and_center_scalar(
            &BigInt::from(ctx.modulus().clone()),
            &BigInt::from(t.to_u64().unwrap()),
        );

        // ZKP modulus (BN254 scalar field)
        let p = get_zkp_modulus();

        // Reduce q_mod_t to standard form for Noir compatibility
        let q_mod_t_mod_p = reduce_scalar(&q_mod_t, &p);

        // CBD bound
        let cbd_bound = (params.variance() * 2) as u64;
        // Uniform bound
        let uniform_bound = (params.get_error1_variance() * BigUint::from(3u32))
            .sqrt()
            .to_bigint()
            .ok_or_else(|| "Failed to convert uniform bound to BigInt".to_string())?;

        let u_bound = SecretKey::sk_bound() as u128; // u_bound is the same as sk_bound

        // e0 = e1 in the fhe.rs
        let e0_bound: u128 = if params.get_error1_variance() <= &BigUint::from(16u32) {
            cbd_bound as u128
        } else {
            uniform_bound.to_u128().unwrap()
        };
        let e1_bound = cbd_bound; // e1 = e2 in the fhe.rs

        // Message bound: message is in [0, t), so bound is t - 1
        let msg_bound = t.clone() - BigInt::from(1);

        let ptxt_up_bound = (t.clone() - BigInt::from(1)) / BigInt::from(2);
        let ptxt_low_bound: BigInt = if (t.clone() % BigInt::from(2)) == BigInt::from(1) {
            -1 * ptxt_up_bound.clone()
        } else {
            -1 * ptxt_up_bound.clone() - BigInt::from(1)
        };

        // Calculate bounds for each CRT basis
        let _num_moduli = ctx.moduli().len();
        let mut pk_bounds: Vec<BigInt> = Vec::new();
        let mut r1_low_bounds: Vec<BigInt> = Vec::new();
        let mut r1_up_bounds: Vec<BigInt> = Vec::new();
        let mut r2_bounds: Vec<BigInt> = Vec::new();
        let mut p1_bounds: Vec<BigInt> = Vec::new();
        let mut p2_bounds: Vec<BigInt> = Vec::new();
        let mut moduli: Vec<u64> = Vec::new();
        let mut k0is: Vec<u64> = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);

            moduli.push(qi.modulus());

            // Calculate k0qi for bounds
            let k0qi = BigInt::from(
                qi.inv(qi.neg(params.plaintext()))
                    .ok_or_else(|| "Failed to calculate modulus inverse for k0qi".to_string())?,
            );
            k0is.push(k0qi.to_u64().unwrap_or(0));

            // PK and R2 bounds (same as qi_bound)
            pk_bounds.push(qi_bound.clone());
            r2_bounds.push(qi_bound.clone());

            let e0_bound_i = e0_bound % qi_bigint.clone();

            // R1 bounds (more complex calculation)
            let r1_low: BigInt = (&ptxt_low_bound * k0qi.abs()
                - &((&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone()))
                / &qi_bigint;
            let r1_up: BigInt = (&ptxt_up_bound * k0qi.abs()
                + ((&n * u_bound + BigInt::from(2)) * &qi_bound + e0_bound_i.clone()))
                / &qi_bigint;

            r1_low_bounds.push(BigInt::from(-1) * r1_low.clone());
            r1_up_bounds.push(r1_up.clone());

            // P1 and P2 bounds
            let p1_bound: BigInt =
                ((&n * u_bound + BigInt::from(2)) * &qi_bound + e1_bound) / &qi_bigint;
            p1_bounds.push(p1_bound.clone());
            p2_bounds.push(qi_bound.clone());
        }

        let crypto_params = EncBfvCryptographicParameters {
            t: params.plaintext(),
            q_mod_t: q_mod_t_mod_p,
            moduli,
            k0is,
        };

        let bounds = EncBfvBounds {
            u_bound: BigUint::from(u_bound as u64),
            e0_bound: BigUint::from(e0_bound),
            e1_bound: BigUint::from(e1_bound),
            msg_bound: BigUint::from(msg_bound.to_u128().unwrap()),
            pk_bounds: pk_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r1_low_bounds: r1_low_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r1_up_bounds: r1_up_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            p1_bounds: p1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            p2_bounds: p2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
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
        let (crypto_params, bounds) = EncBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert_eq!(crypto_params.k0is.len(), 1);
        assert_eq!(bounds.pk_bounds.len(), 1);
        assert_eq!(bounds.r1_low_bounds.len(), 1);
        assert_eq!(bounds.r1_up_bounds.len(), 1);
        assert_eq!(bounds.r2_bounds.len(), 1);
        assert_eq!(bounds.p1_bounds.len(), 1);
        assert_eq!(bounds.p2_bounds.len(), 1);
    }
}
