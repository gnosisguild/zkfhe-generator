use fhe::bfv::BfvParameters;
use num_bigint::{BigInt, BigUint};
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
    /// Bound for public key polynomials (pk0, pk1)
    /// Used for commitment bit width calculation
    pub pk_bound: BigUint,
}

impl PkBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `level` - The CRT level to compute bounds for
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
    ) -> ZkFheResult<(PkBfvCryptographicParameters, Self)> {
        let ctx = params.ctx_at_level(level)?;

        // Calculate bounds for each CRT basis
        let mut moduli = Vec::new();
        let mut pk_bound_max = BigInt::from(0);

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(qi.modulus());

            // Track maximum pk bound across all moduli
            if qi_bound > pk_bound_max {
                pk_bound_max = qi_bound;
            }
        }

        let crypto_params = PkBfvCryptographicParameters { moduli };

        let bounds = PkBfvBounds {
            pk_bound: BigUint::from(pk_bound_max.to_u128().unwrap()),
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
            "pk_bound": self.pk_bound
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_bfv;

    #[test]
    fn test_bounds_computation() {
        let params = test_parameters_bfv();
        let (crypto_params, bounds) = PkBfvBounds::compute(&params, 0).unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert!(bounds.pk_bound > BigUint::from(0u32));
    }
}
