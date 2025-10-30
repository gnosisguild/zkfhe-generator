use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for PkTrBfv circuit
#[derive(Clone, Debug)]
pub struct PkTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
}

/// Bounds for PkTrBfv circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct PkTrBfvBounds {
    // Bounds for different polynomial types
    pub eek_bound: u64,
    pub sk_bound: u64,
    pub r1_low_bounds: Vec<i64>,
    pub r1_up_bounds: Vec<u64>,
    pub r2_bounds: Vec<u64>,
}

impl PkTrBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(PkTrBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let ctx = params.ctx_at_level(level)?;

        // Gaussian bound for error polynomials (6σ)
        let gauss_bound = BigInt::from(
            f64::ceil(6_f64 * f64::sqrt(params.variance() as f64))
                .to_i64()
                .ok_or_else(|| "Failed to convert variance to i64".to_string())?,
        );

        let sk_bound = gauss_bound.clone();
        let eek_bound = gauss_bound.clone();

        // Calculate bounds for each CRT basis
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_low_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_up_bounds = vec![BigInt::from(0); num_moduli];
        let mut moduli = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(qi.modulus());

            r2_bounds[i] = qi_bound.clone();

            // Compute asymmetric range for r1 bounds per modulus
            r1_low_bounds[i] =
                (-((&n * &gauss_bound + 2u32) * &qi_bound + &gauss_bound)) / &qi_bigint;
            r1_up_bounds[i] = ((&n * &gauss_bound + 2u32) * &qi_bound + &gauss_bound) / &qi_bigint;
        }

        // Convert bounds to primitive types for serialization into Noir or test fixtures
        let sk_bound_u64 = sk_bound.to_u64().unwrap_or(19);
        let eek_bound_u64 = eek_bound.to_u64().unwrap_or(19);
        let r1_low_bounds_i64 = r1_low_bounds
            .iter()
            .map(|b| b.to_i64().unwrap_or(0))
            .collect();
        let r1_up_bounds_u64 = r1_up_bounds
            .iter()
            .map(|b| b.to_u64().unwrap_or(0))
            .collect();
        let r2_bounds_u64 = r2_bounds.iter().map(|b| b.to_u64().unwrap_or(0)).collect();

        let crypto_params = PkTrBfvCryptographicParameters { moduli };

        let bounds = PkTrBfvBounds {
            eek_bound: eek_bound_u64,
            sk_bound: sk_bound_u64,
            r1_low_bounds: r1_low_bounds_i64,
            r1_up_bounds: r1_up_bounds_u64,
            r2_bounds: r2_bounds_u64,
        };

        Ok((crypto_params, bounds))
    }
}

impl PkTrBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli
        })
    }
}

impl PkTrBfvBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "eek_bound": self.eek_bound,
            "sk_bound": self.sk_bound,
            "r1_low_bounds": self.r1_low_bounds,
            "r1_up_bounds": self.r1_up_bounds,
            "r2_bounds": self.r2_bounds
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
        let (crypto_params, bounds) = PkTrBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert_eq!(bounds.eek_bound, 19);
        assert_eq!(bounds.sk_bound, 19);
        assert_eq!(bounds.r1_low_bounds.len(), 1);
        assert_eq!(bounds.r1_up_bounds.len(), 1);
        assert_eq!(bounds.r2_bounds.len(), 1);
    }

    #[test]
    fn test_bounds_invalid_level() {
        let params = setup_test_params();
        let result = PkTrBfvBounds::compute(&params, 1);
        assert!(result.is_err());
    }
}
