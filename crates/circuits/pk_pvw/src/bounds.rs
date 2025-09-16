use num_traits::ToPrimitive;
use pvw::PvwParameters;
use shared::errors::ZkFheResult;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct PkPvwCryptographicParameters {
    pub qis: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct PkPvwBounds {
    /// Bound for error polynomials (e)
    pub e_bound: u64,
    /// Bound for secret key polynomials (sk)
    pub sk_bound: u64,
    /// Lower bounds for r1 polynomials (modulus switching quotients)
    pub r1_low_bounds: Vec<i64>,
    /// Upper bounds for r1 polynomials (modulus switching quotients)
    pub r1_up_bounds: Vec<u64>,
    /// Bounds for r2 polynomials (cyclotomic reduction quotients)
    pub r2_bounds: Vec<u64>,
}

impl PkPvwBounds {
    pub fn compute(
        params: &Arc<PvwParameters>,
        _level: usize,
    ) -> ZkFheResult<(PkPvwCryptographicParameters, Self)> {
        // Extract moduli from PvwParameters
        let moduli = params.moduli();
        let qis: Vec<u64> = moduli.to_vec();

        // Extract parameters for bounds calculation
        let n = params.l; // Ring dimension N from context degree
        let error_bound = params.error_bound_1.to_u64().unwrap(); // B (error bound)
        let secret_variance = params.secret_variance as u64; // B_s (secret key bound)

        // Calculate bounds for each modulus
        let mut r1_low_bounds = Vec::new();
        let mut r1_up_bounds = Vec::new();
        let mut r2_bounds = Vec::new();

        for &qi in &qis {
            // b_{l,i} ∈ [-⌊(q_l-1)/2⌋, ⌊(q_l-1)/2⌋]
            // r2_{l,i} ∈ [-⌊(q_l-1)/2⌋, ⌊(q_l-1)/2⌋]
            // a_l ∈ [-⌊(q_l-1)/2⌋, ⌊(q_l-1)/2⌋]
            let qi_bound = (qi - 1) / 2;
            r2_bounds.push(qi_bound);

            // r1_{l,i} ∈ [⌊(-((N * B_s + 2) * ⌊(q_l-1)/2⌋ + B)) / q_l⌋, ⌊((N * B_s + 2) * ⌊(q_l-1)/2⌋ + B) / q_l⌋]
            let numerator = (n as u64 * secret_variance + 2) * qi_bound + error_bound;
            let r1_up = numerator / qi;
            let r1_low = -((numerator / qi) as i64);

            r1_low_bounds.push(r1_low);
            r1_up_bounds.push(r1_up);
        }

        let crypto_params = PkPvwCryptographicParameters { qis };
        let bounds = PkPvwBounds {
            e_bound: error_bound,
            sk_bound: secret_variance,
            r1_low_bounds,
            r1_up_bounds,
            r2_bounds,
        };

        Ok((crypto_params, bounds))
    }
}

impl PkPvwCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "qis": self.qis })
    }
}

impl PkPvwBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "e_bound": self.e_bound, "sk_bound": self.sk_bound, "r1_low_bounds": self.r1_low_bounds, "r1_up_bounds": self.r1_up_bounds, "r2_bounds": self.r2_bounds })
    }
}
