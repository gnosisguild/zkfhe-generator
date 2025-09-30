use pvw::PvwParameters;
use shared::errors::ZkFheResult;
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct SkSharesCryptographicParameters {
    pub qis: Vec<u64>,
}

#[derive(Clone, Debug)]
pub struct SkSharesBounds {
    /// Bound for secret key coefficients
    pub sk_bound: u64,
    /// Lower bound for r polynomials
    pub r_lower_bound: i64,
    /// Upper bound for r polynomials
    pub r_upper_bound: u64,
    /// Bound for commitment randomness
    pub randomness_bound: u64,
}

impl SkSharesBounds {
    pub fn compute(
        params: &Arc<PvwParameters>,
    ) -> ZkFheResult<(SkSharesCryptographicParameters, Self)> {
        let moduli = params.moduli();
        let qis: Vec<u64> = moduli.to_vec();
        let randomness_bound: u64 = qis.iter().copied().map(|q| (q - 1) / 2).max().unwrap_or(0);
        let (r_lower_bound, r_upper_bound) = derive_sss_r_bounds(params.n, params.t);
        let sk_bound: u64 = 20;

        let crypto_params = SkSharesCryptographicParameters { qis };
        let bounds = SkSharesBounds {
            sk_bound,
            r_lower_bound,
            r_upper_bound,
            randomness_bound,
        };

        Ok((crypto_params, bounds))
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sk_bound": self.sk_bound,
            "r_lower_bound": self.r_lower_bound,
            "r_upper_bound": self.r_upper_bound,
            "randomness_bound": self.randomness_bound
        })
    }
}

impl SkSharesCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({ "qis": self.qis })
    }
}

fn geometric_sum_u128(base: usize, terms: usize) -> u128 {
    if terms == 0 {
        return 0;
    }
    let mut s: u128 = 0;
    let mut pow: u128 = 1;
    for _ in 0..terms {
        s = s.saturating_add(pow);
        pow = pow.saturating_mul(base as u128);
    }
    s
}

fn derive_sss_r_bounds(n_parties: usize, t: usize) -> (i64, u64) {
    let s = geometric_sum_u128(n_parties, t);
    let upper = s.saturating_sub(1);
    let upper_u64 = if upper > u64::MAX as u128 {
        u64::MAX
    } else {
        upper as u64
    };
    (0_i64, upper_u64)
}
