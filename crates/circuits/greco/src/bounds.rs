//! Bounds calculation for Greco zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! and validation that input vectors stay within these bounds.

use bigint_poly::{reduce_and_center_scalar, reduce_scalar};
use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
use num_traits::{Signed, ToPrimitive};
use shared::constants::get_zkp_modulus;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for Greco circuit
#[derive(Clone, Debug)]
pub struct GrecoCryptographicParameters {
    pub q_mod_t: BigInt,
    pub moduli: Vec<u64>,
    pub k0is: Vec<u64>,
}

/// Bounds for Greco circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct GrecoBounds {
    // Bounds for different polynomial types
    pub u_bound: u64,
    pub e_bound: u64,
    pub k1_low_bound: i64,
    pub k1_up_bound: u64,
    pub pk_bounds: Vec<u64>,
    pub r1_low_bounds: Vec<i64>,
    pub r1_up_bounds: Vec<u64>,
    pub r2_bounds: Vec<u64>,
    pub p1_bounds: Vec<u64>,
    pub p2_bounds: Vec<u64>,
}

impl GrecoBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(GrecoCryptographicParameters, Self)> {
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

        // Gaussian bound for error polynomials (6σ)
        let gauss_bound = BigInt::from(
            f64::ceil(6_f64 * f64::sqrt(params.variance() as f64))
                .to_i64()
                .ok_or_else(|| "Failed to convert variance to i64".to_string())?,
        );

        let u_bound = gauss_bound.clone();
        let e_bound = gauss_bound.clone();

        // Note we have two different variables for lower bound and upper bound, as in the case
        // where the plaintext modulus is even, the lower bound cannot be calculated by just
        // negating the upper bound. For instance, if t = 8, then the lower bound will be -4 and the
        // upper bound will be 3
        let ptxt_up_bound = (t.clone() - BigInt::from(1)) / BigInt::from(2);
        let ptxt_low_bound = if (t.clone() % BigInt::from(2)) == BigInt::from(1) {
            (-&(t.clone() - BigInt::from(1))) / BigInt::from(2)
        } else {
            ((-&(t.clone() - BigInt::from(1))) / BigInt::from(2)) - BigInt::from(1)
        };

        let k1_low_bound = ptxt_low_bound.clone();
        let k1_up_bound = ptxt_up_bound.clone();

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

            // R1 bounds (more complex calculation)
            let r1_low: BigInt = (&ptxt_low_bound * k0qi.abs()
                - &((&n * &gauss_bound + BigInt::from(2)) * &qi_bound + &gauss_bound))
                / &qi_bigint;
            let r1_up: BigInt = (&ptxt_up_bound * k0qi.abs()
                + ((&n * &gauss_bound + BigInt::from(2)) * &qi_bound + &gauss_bound))
                / &qi_bigint;

            r1_low_bounds.push(r1_low.clone());
            r1_up_bounds.push(r1_up.clone());

            // P1 and P2 bounds
            let p1_bound: BigInt =
                ((&n * &gauss_bound + BigInt::from(2)) * &qi_bound + &gauss_bound) / &qi_bigint;
            p1_bounds.push(p1_bound.clone());
            p2_bounds.push(qi_bound.clone());
        }

        let crypto_params = GrecoCryptographicParameters {
            q_mod_t: q_mod_t_mod_p,
            moduli,
            k0is,
        };

        let bounds = GrecoBounds {
            u_bound: u_bound.to_u64().unwrap(),
            e_bound: e_bound.to_u64().unwrap(),
            k1_low_bound: k1_low_bound.to_i64().unwrap(),
            k1_up_bound: k1_up_bound.to_u64().unwrap(),
            pk_bounds: pk_bounds.iter().map(|b| b.to_u64().unwrap()).collect(),
            r1_low_bounds: r1_low_bounds.iter().map(|b| b.to_i64().unwrap()).collect(),
            r1_up_bounds: r1_up_bounds.iter().map(|b| b.to_u64().unwrap()).collect(),
            r2_bounds: r2_bounds.iter().map(|b| b.to_u64().unwrap()).collect(),
            p1_bounds: p1_bounds.iter().map(|b| b.to_u64().unwrap()).collect(),
            p2_bounds: p2_bounds.iter().map(|b| b.to_u64().unwrap()).collect(),
        };

        Ok((crypto_params, bounds))
    }
}

impl GrecoCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "q_mod_t": self.q_mod_t.to_string(),
            "moduli": self.moduli,
            "k0is": self.k0is,
        })
    }
}

impl GrecoBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "u_bound": self.u_bound,
            "e_bound": self.e_bound,
            "k1_low_bound": self.k1_low_bound,
            "k1_up_bound": self.k1_up_bound,
            "pk_bounds": self.pk_bounds,
            "r1_low_bounds": self.r1_low_bounds,
            "r1_up_bounds": self.r1_up_bounds,
            "r2_bounds": self.r2_bounds,
            "p1_bounds": self.p1_bounds,
            "p2_bounds": self.p2_bounds,
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
            .build_arc()
            .unwrap()
    }

    #[test]
    fn test_bounds_computation() {
        let params = setup_test_params();
        let (crypto_params, bounds) = GrecoBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert_eq!(crypto_params.k0is.len(), 1);
        assert_eq!(bounds.pk_bounds.len(), 1);
        assert_eq!(bounds.r1_low_bounds.len(), 1);
        assert_eq!(bounds.r1_up_bounds.len(), 1);
        assert_eq!(bounds.r2_bounds.len(), 1);
        assert_eq!(bounds.p1_bounds.len(), 1);
        assert_eq!(bounds.p2_bounds.len(), 1);
    }

    #[test]
    fn test_bounds_invalid_level() {
        let params = setup_test_params();
        let result = GrecoBounds::compute(&params, 1);
        assert!(result.is_err());
    }
}
