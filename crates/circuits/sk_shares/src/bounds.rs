use num_bigint::BigUint;
use num_traits::One;
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
        pvw_params: &Arc<PvwParameters>,
    ) -> ZkFheResult<(SkSharesCryptographicParameters, Self)> {
        let moduli = pvw_params.moduli();
        let qis = moduli.to_vec();
        let randomness_bound = qis.iter().copied().map(|q| (q - 1) / 2).max().unwrap_or(0);
        let (r_lower_bound, r_upper_bound) = r_bounds(pvw_params.n, pvw_params.t, moduli);
        let sk_bound = 1;

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

pub fn r_bounds(n: usize, t: usize, qjs: &[u64]) -> (i64, u64) {
    assert!(n > 0, "n must be > 0");
    assert!(t > 0, "t must be > 0");
    assert!(!qjs.is_empty(), "qjs must be non-empty");

    let n_big = BigUint::from(n as u64);
    let n_power = n_big.pow(t as u32);
    let s = (n_power - BigUint::one()) / (n - 1);

    let mut lowers = Vec::with_capacity(qjs.len());
    let mut uppers = Vec::with_capacity(qjs.len());

    for &q in qjs {
        assert!(q > 0, "q_j must be > 0");

        let q_big = BigUint::from(q);
        let qm1 = &q_big - BigUint::one(); // q-1
        let num = &qm1 * &s; // (q-1) * S
        let den = &q_big << 1; // 2*q

        // TODO: Doesnt fit
        let _r_abs: BigUint = (&num + (&den - BigUint::one())) / &den;

        let r_abs_u64 = i64::MAX as u64 - 1;
        assert!(r_abs_u64 <= i64::MAX as u64, "r_abs doesn't fit in i64");

        uppers.push(r_abs_u64);
        lowers.push(-(r_abs_u64 as i64));
    }

    (lowers[0], uppers[0])
}
