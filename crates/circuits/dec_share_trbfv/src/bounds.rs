use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Cryptographic parameters for DecShareTrBfv circuit
#[derive(Clone, Debug)]
pub struct DecShareTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
    pub k0is: Vec<u64>, // Scaling factors (can be ignored per user's note)
}

/// Bounds for DecShareTrBfv circuit polynomial coefficients
///
/// Note: After removing `collected_shares` and `collected_noise` from the circuit,
/// `noise_bound` and `share_bounds` are only used internally to compute other bounds
/// (s_bound, e_bound, r1_bounds) and are not directly checked by the circuit.
#[derive(Clone, Debug)]
pub struct DecShareTrBfvBounds {
    /// Bound for smudging noise shares e_i (Be from notes)
    pub noise_bound: u64,
    /// Bounds for valid shares y_i for each honest party (Bs from notes)
    pub share_bounds: Vec<u64>,
    /// Bound for aggregated shares sum s = ∑ y_i (checked by circuit)
    pub s_bound: u64,
    /// Bound for aggregated noise sum e = ∑ e_i (checked by circuit)
    pub e_bound: u64,
    /// Bound for computed decryption share d (checked by circuit)
    pub decryption_share_bound: u64,
    /// Lower bounds for r_1 polynomials (modulus quotients, can be negative, checked by circuit)
    pub r1_low_bounds: Vec<i64>,
    /// Upper bounds for r_1 polynomials (modulus quotients, checked by circuit)
    pub r1_up_bounds: Vec<u64>,
    /// Bounds for r_2 polynomials (cyclotomic quotients, checked by circuit)
    pub r2_bounds: Vec<u64>,
}

impl DecShareTrBfvBounds {
    /// Compute bounds and cryptographic parameters from BFV parameters
    ///
    /// Based on handwritten notes formulas:
    /// - r2j: [- (qj-1)/2, (qj-1)/2]
    /// - rij: [- (qj-1)/2 * (Bs*N+3) - Be / qj, (qj-1)/2 * (Bs*N+3) + Be / qj]
    /// - d_j: [- (qj-1)/2, (qj-1)/2]
    /// - s_bound = ∑ share_bounds[i]
    /// - e_bound = H * noise_bound
    pub fn compute(
        params: &Arc<BfvParameters>,
        level: usize,
        noise_bound: u64,
        share_bounds: Vec<u64>,
        honest_parties: usize,
    ) -> ZkFheResult<(DecShareTrBfvCryptographicParameters, Self)> {
        // Get cyclotomic degree and context at provided level
        let n = BigInt::from(params.degree());
        let ctx = params.ctx_at_level(level)?;

        // Be = noise_bound
        let be = BigInt::from(noise_bound);

        // Bs = max(share_bounds) - maximum share bound
        let bs = share_bounds
            .iter()
            .max()
            .ok_or_else(|| "share_bounds cannot be empty".to_string())?;
        let bs_bigint = BigInt::from(*bs);

        // Calculate bounds for each CRT basis
        let num_moduli = ctx.moduli().len();
        let mut r2_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_low_bounds = vec![BigInt::from(0); num_moduli];
        let mut r1_up_bounds = vec![BigInt::from(0); num_moduli];
        let mut decryption_share_bounds = vec![BigInt::from(0); num_moduli];
        let mut moduli = Vec::new();
        let mut k0is = Vec::new();

        for (i, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let qi_bound = (&qi_bigint - 1u32) / 2u32;

            moduli.push(qi.modulus());
            k0is.push(0u64); // Placeholder, can be ignored per user's note

            // r2j bounds: [- (qj-1)/2, (qj-1)/2]
            r2_bounds[i] = qi_bound.clone();

            // d_j bounds: [- (qj-1)/2, (qj-1)/2]
            decryption_share_bounds[i] = qi_bound.clone();

            // rij bounds: [- (qj-1)/2 * (Bs*N+3) - Be / qj, (qj-1)/2 * (Bs*N+3) + Be / qj]
            let bs_n_plus_3 = &bs_bigint * &n + BigInt::from(3u32);
            let numerator_low = -(&qi_bound * &bs_n_plus_3) - &be;
            let numerator_up = &qi_bound * &bs_n_plus_3 + &be;

            r1_low_bounds[i] = &numerator_low / &qi_bigint;
            r1_up_bounds[i] = &numerator_up / &qi_bigint;
        }

        // s_bound = ∑ share_bounds[i]
        let s_bound = share_bounds.iter().sum::<u64>();

        // e_bound = H * noise_bound (since e = ∑ e_i where each e_i is bounded by noise_bound)
        let e_bound = honest_parties as u64 * noise_bound;

        // decryption_share_bound: use the maximum across all moduli
        let decryption_share_bound = decryption_share_bounds
            .iter()
            .map(|b| b.to_u64().unwrap_or(0))
            .max()
            .unwrap_or(0);

        // Convert bounds to primitive types for serialization into Noir or test fixtures
        let noise_bound_u64 = noise_bound;
        let r1_low_bounds_i64 = r1_low_bounds
            .iter()
            .map(|b| b.to_i64().unwrap_or(0))
            .collect();
        let r1_up_bounds_u64 = r1_up_bounds
            .iter()
            .map(|b| b.to_u64().unwrap_or(0))
            .collect();
        let r2_bounds_u64 = r2_bounds.iter().map(|b| b.to_u64().unwrap_or(0)).collect();

        let crypto_params = DecShareTrBfvCryptographicParameters { moduli, k0is };

        let bounds = DecShareTrBfvBounds {
            noise_bound: noise_bound_u64,
            share_bounds,
            s_bound,
            e_bound,
            decryption_share_bound,
            r1_low_bounds: r1_low_bounds_i64,
            r1_up_bounds: r1_up_bounds_u64,
            r2_bounds: r2_bounds_u64,
        };

        Ok((crypto_params, bounds))
    }
}

impl DecShareTrBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli,
            // "k0is": self.k0is
        })
    }
}

impl DecShareTrBfvBounds {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "noise_bound": self.noise_bound,
            "share_bounds": self.share_bounds,
            "s_bound": self.s_bound,
            "e_bound": self.e_bound,
            "decryption_share_bound": self.decryption_share_bound,
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
        let noise_bound = 19u64;
        let share_bounds = vec![19u64, 19u64, 19u64]; // Example: 3 honest parties
        let honest_parties = share_bounds.len();

        let (crypto_params, bounds) =
            DecShareTrBfvBounds::compute(&params, 0, noise_bound, share_bounds, honest_parties)
                .unwrap();

        assert_eq!(crypto_params.moduli.len(), 1);
        assert_eq!(bounds.noise_bound, noise_bound);
        assert_eq!(bounds.share_bounds.len(), honest_parties);
        assert_eq!(bounds.s_bound, 19 * honest_parties as u64);
        assert_eq!(bounds.e_bound, noise_bound * honest_parties as u64);
        assert_eq!(bounds.r1_low_bounds.len(), 1);
        assert_eq!(bounds.r1_up_bounds.len(), 1);
        assert_eq!(bounds.r2_bounds.len(), 1);
    }

    #[test]
    fn test_bounds_invalid_level() {
        let params = setup_test_params();
        let result = DecShareTrBfvBounds::compute(&params, 1, 19, vec![19], 1);
        assert!(result.is_err());
    }
}
