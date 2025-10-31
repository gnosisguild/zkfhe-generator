//! Bounds calculation for Decryption Share TRBFV zero-knowledge proofs.
//!
//! This module handles the computation of valid ranges for polynomial coefficients
//! used in threshold BFV decryption share correctness verification.
//!
//! Based on the mathematical analysis:
//! - d_j = c_0j + c_1j * s + e + r_2j * (X^N + 1) + r_1j * q_j (mod Z)
//! - Where s = Σy_i (aggregated shares) and e = Σe_i (aggregated noise)

use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
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
    /// Bound for aggregated shares sum s = Σy_i
    pub s_bound: u64,
    /// Bound for aggregated noise sum e = Σe_i
    pub e_bound: u64,
    /// Bound for computed decryption share d (maximum across all moduli)
    pub decryption_share_bound: u64,
    /// Lower bounds for r_1 polynomials (modulus quotients, can be negative)
    pub r1_low_bounds: Vec<i64>,
    /// Upper bounds for r_1 polynomials (modulus quotients)
    pub r1_up_bounds: Vec<u64>,
    /// Bounds for r_2 polynomials (cyclotomic quotients)
    pub r2_bounds: Vec<u64>,
}

impl DecShareTrBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `num_ciphertexts` - Number of shares being summed in aggregation (defaults to 10 if None)
    /// * `level` - The CRT level to compute bounds for
    ///
    /// # Returns
    /// A tuple of (cryptographic parameters, bounds)
    pub fn compute(
        params: &Arc<BfvParameters>,
        num_ciphertexts: usize,
        level: usize,
    ) -> ZkFheResult<(DecShareTrBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let ctx = params.ctx_at_level(level)?;

        // Gaussian bound for error polynomials (6σ)
        let gauss_bound = BigInt::from(
            f64::ceil(6_f64 * f64::sqrt(params.variance() as f64))
                .to_i64()
                .ok_or_else(|| "Failed to convert variance to i64".to_string())?,
        );

        // Bound for aggregated shares s = Σy_i
        // Each share is small (bounded by gauss_bound), and we sum num_ciphertexts shares
        // Using a conservative bound: num_ciphertexts * gauss_bound * sqrt(n) to account for
        // polynomial multiplication effects
        let s_bound = (&BigInt::from(num_ciphertexts) * &gauss_bound * n.sqrt())
            .to_u64()
            .unwrap_or_else(|| num_ciphertexts as u64 * gauss_bound.to_u64().unwrap());

        // Bound for aggregated noise e = Σe_i
        // Using the same variance as for shares (can be adjusted if error2_variance is different)
        let e_bound = (&BigInt::from(num_ciphertexts) * &gauss_bound * n.sqrt())
            .to_u64()
            .unwrap_or_else(|| num_ciphertexts as u64 * gauss_bound.to_u64().unwrap());

        // Convert to BigInt for calculations
        let s_bound_big = BigInt::from(s_bound);
        let e_bound_big = BigInt::from(e_bound);

        // Calculate bounds for each CRT basis
        let mut decryption_share_bound_max = BigInt::from(0);
        let mut r1_low_bounds: Vec<BigInt> = Vec::new();
        let mut r1_up_bounds: Vec<BigInt> = Vec::new();
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
            // r_1j: [((q_j-1)/2 * (BS.N+3) - Be) / q_j , ((q_j-1)/2 * (BS.N+3) + Be) / q_j]
            // Where BS = s_bound, Be = e_bound, N = n (degree)
            let r1_low: BigInt =
                (&qi_bound * (&s_bound_big * &n + BigInt::from(3)) - &e_bound_big) / &qi_bigint;
            let r1_up: BigInt =
                (&qi_bound * (&s_bound_big * &n + BigInt::from(3)) + &e_bound_big) / &qi_bigint;

            r1_low_bounds.push(r1_low.clone());
            r1_up_bounds.push(r1_up.clone());
        }

        let crypto_params = DecShareTrBfvCryptographicParameters { moduli };

        let bounds = DecShareTrBfvBounds {
            s_bound,
            e_bound,
            decryption_share_bound: decryption_share_bound_max.to_u64().unwrap_or(0),
            r1_low_bounds: r1_low_bounds
                .iter()
                .map(|b| b.to_i64().unwrap_or(0))
                .collect(),
            r1_up_bounds: r1_up_bounds
                .iter()
                .map(|b| b.to_u64().unwrap_or(0))
                .collect(),
            r2_bounds: r2_bounds.iter().map(|b| b.to_u64().unwrap_or(0)).collect(),
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
            "s_bound": self.s_bound,
            "e_bound": self.e_bound,
            "decryption_share_bound": self.decryption_share_bound,
            "r1_low_bounds": self.r1_low_bounds,
            "r1_up_bounds": self.r1_up_bounds,
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
        let (crypto_params, bounds) = DecShareTrBfvBounds::compute(&params, 10, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert_eq!(bounds.r1_low_bounds.len(), 1);
        assert_eq!(bounds.r1_up_bounds.len(), 1);
        assert_eq!(bounds.r2_bounds.len(), 1);
        assert!(bounds.s_bound > 0);
        assert!(bounds.e_bound > 0);
        assert!(bounds.decryption_share_bound > 0);
    }
}
