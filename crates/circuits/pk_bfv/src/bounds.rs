use fhe::bfv::BfvParameters;
use fhe::bfv::SecretKey;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for PkBfv circuit
#[derive(Clone, Debug)]
pub struct PkBfvCryptographicParameters {
    pub moduli: Vec<u64>,
}

/// Bounds for PkBfv circuit polynomial coefficients
#[derive(Clone, Debug)]
pub struct PkBfvBounds {
    // Bounds for different polynomial types
    pub eek_bound: BigUint,
    pub sk_bound: BigUint,
    pub r1_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
}

impl PkBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(PkBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let ctx = params.ctx_at_level(level)?;

        // CBD bound
        let cbd_bound = (params.variance() * 2) as u64;

        let sk_bound = SecretKey::sk_bound();
        let eek_bound = cbd_bound;

        // Calculate bounds for each CRT basis
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_bounds = vec![BigInt::from(0); num_moduli];
        let mut moduli = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(qi.modulus());

            r2_bounds[i] = qi_bound.clone();

            // Compute asymmetric range for r1 bounds per modulus
            r1_bounds[i] = ((&n * eek_bound + 2u32) * &qi_bound + eek_bound) / &qi_bigint;
        }

        let crypto_params = PkBfvCryptographicParameters { moduli };

        let bounds = PkBfvBounds {
            eek_bound: BigUint::from(eek_bound),
            sk_bound: BigUint::from(sk_bound as u128),
            r1_bounds: r1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
        };

        Ok((crypto_params, bounds))
    }
}

impl PkBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli
        })
    }
}

impl PkBfvBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "eek_bound": self.eek_bound,
            "sk_bound": self.sk_bound,
            "r1_bounds": self.r1_bounds,
            "r2_bounds": self.r2_bounds
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
        let (crypto_params, bounds) = PkBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 2);
        assert_eq!(bounds.r1_bounds.len(), 2);
        assert_eq!(bounds.r2_bounds.len(), 2);
    }
}
