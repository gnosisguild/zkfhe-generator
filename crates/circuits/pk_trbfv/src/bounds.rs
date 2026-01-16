use fhe::bfv::BfvParameters;
use fhe::bfv::SecretKey;
use fhe::trbfv::{SmudgingBoundCalculator, SmudgingBoundCalculatorConfig};
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_traits::ToPrimitive;
use shared::circuit::CiphernodesConfig;
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
    pub eek_bound: BigUint,
    pub sk_bound: BigUint,
    /// Bound for smudging noise polynomial (e_sm) coefficients
    pub e_sm_bound: BigUint,
    pub r1_bounds: Vec<BigUint>,
    pub r2_bounds: Vec<BigUint>,
    /// Bound for public key polynomials (pk0, pk1)
    /// Used for commitment bit width calculation
    pub pk_bound: BigUint,
}

impl PkTrBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    ///
    /// # Arguments
    /// * `params` - BFV parameters
    /// * `level` - The CRT level to compute bounds for
    /// * `lambda` - Security parameter for smudging noise bound calculation
    /// * `ciphernodes_config` - Configuration with num_parties and threshold for smudging bound calculation
    /// * `num_ciphertexts` - Number of ciphertexts being processed (for smudging bound calculation)
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
        lambda: usize,
        ciphernodes_config: &CiphernodesConfig,
        num_ciphertexts: usize,
    ) -> ZkFheResult<(PkTrBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let ctx = params.ctx_at_level(level)?;

        // CBD bound
        let cbd_bound = (params.variance() * 2) as u64;

        let sk_bound = SecretKey::sk_bound();
        let eek_bound = cbd_bound;

        // Calculate smudging noise bound using SmudgingBoundCalculator from fhe.rs
        let smudging_config = SmudgingBoundCalculatorConfig::new(
            params.clone(),
            ciphernodes_config.num_parties,
            num_ciphertexts,
            lambda,
        );
        let smudging_calculator = SmudgingBoundCalculator::new(smudging_config);
        let e_sm_bound = smudging_calculator.calculate_sm_bound().map_err(|e| {
            shared::errors::ZkFheError::Bfv {
                message: format!("Failed to calculate smudging bound: {:?}", e),
            }
        })?;

        // Calculate bounds for each CRT basis
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_bounds = vec![BigInt::from(0); num_moduli];
        let mut moduli = Vec::new();
        let mut pk_bound_max = BigInt::from(0);

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(qi.modulus());

            r2_bounds[i] = qi_bound.clone();

            // Compute asymmetric range for r1 bounds per modulus
            r1_bounds[i] = ((&n * eek_bound + 2u32) * &qi_bound + eek_bound) / &qi_bigint;

            // Track maximum pk bound across all moduli
            // We don't need to store them as we only need the maximum bound to compute the commitment bit width
            if qi_bound > pk_bound_max {
                pk_bound_max = qi_bound;
            }
        }

        let crypto_params = PkTrBfvCryptographicParameters { moduli };

        let bounds = PkTrBfvBounds {
            eek_bound: BigUint::from(eek_bound),
            sk_bound: BigUint::from(sk_bound as u128),
            e_sm_bound,
            r1_bounds: r1_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            r2_bounds: r2_bounds
                .iter()
                .map(|b| BigUint::from(b.to_u128().unwrap()))
                .collect(),
            pk_bound: BigUint::from(pk_bound_max.to_u128().unwrap()),
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
            "e_sm_bound": self.e_sm_bound,
            "r1_bounds": self.r1_bounds,
            "r2_bounds": self.r2_bounds,
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
        let lambda = shared::DEFAULT_INSECURE_LAMBDA;
        let ciphernodes_config = CiphernodesConfig::defaults();
        let num_ciphertexts = 1;
        let (crypto_params, bounds) =
            PkTrBfvBounds::compute(&params, 0, lambda, &ciphernodes_config, num_ciphertexts)
                .unwrap();

        assert_eq!(crypto_params.moduli.len(), 2);
        assert_eq!(bounds.r1_bounds.len(), 2);
        assert_eq!(bounds.r2_bounds.len(), 2);
        // e_sm_bound should be calculated by SmudgingBoundCalculator
        assert!(bounds.e_sm_bound > BigUint::from(0u32));
    }
}
