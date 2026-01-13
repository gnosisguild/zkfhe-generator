use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for PkAggTrBfv circuit
#[derive(Clone, Debug)]
pub struct PkAggTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
    /// Bound for public key polynomials (pk0, pk1)
    /// Used for commitment bit width calculation
    pub pk_bound: BigUint,
}

impl PkAggTrBfvCryptographicParameters {
    /// Compute cryptographic parameters and bounds from BFV parameters
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `level` - The CRT level to compute bounds for
    ///
    /// # Returns
    /// Cryptographic parameters including moduli and pk_bound
    pub fn compute(params: &Arc<BfvParameters>, level: usize) -> ZkFheResult<Self> {
        let ctx = params.ctx_at_level(level)?;

        // Compute pk_bound as the maximum bound across all moduli
        // This ensures the bit width is sufficient for all moduli
        let mut pk_bound_max = BigInt::from(0);
        let mut moduli = Vec::new();

        for qi in ctx.moduli_operators() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - BigInt::from(1)) / BigInt::from(2);
            if qi_bound > pk_bound_max {
                pk_bound_max = qi_bound;
            }
            moduli.push(qi.modulus());
        }

        Ok(Self {
            moduli,
            pk_bound: BigUint::from(pk_bound_max.to_u128().ok_or_else(|| {
                shared::errors::ZkFheError::Bfv {
                    message: "pk_bound_max does not fit in u128".to_string(),
                }
            })?),
        })
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli,
            "pk_bound": self.pk_bound
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
        let crypto_params = PkAggTrBfvCryptographicParameters::compute(&params, 0).unwrap();
        assert_eq!(crypto_params.moduli.len(), params.moduli().len());
        assert!(crypto_params.pk_bound > BigUint::from(0u32));
    }
}
