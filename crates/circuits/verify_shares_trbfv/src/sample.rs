//! Sample data generation for Secret Key Shares verification circuit
//!
//! This module generates sample secret key shares data needed for the zero-knowledge
//! proof circuit. It simulates the generation of Shamir secret shares for a secret key
//! and computes the parity check matrices for verification.

use fhe::bfv::{BfvParameters, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use num_bigint::{BigInt, BigUint};
use parity_matrix::matrix::{ParityMatrixConfig, build_generator_matrix, null_space};
use rand::rngs::OsRng;
use shared::circuit::{CiphernodesConfig, SampleType};
use std::sync::Arc;

/// Data from a sample verify shares TRBFV generation
#[derive(Debug, Clone)]
pub struct VerifySharesTrbfvData {
    /// Secret coefficients (can be either secret key trinary coefficients or smudging noise)
    /// For secret key: trinary coefficients {-1, 0, 1}
    /// For smudging noise: the actual smudging noise coefficients (can be large values)
    pub secret_coeffs: Vec<BigInt>,
    /// Shamir secret shares: sk_sss[modulus_idx][party_idx][coeff_idx]
    /// Gives the share that party_idx has for coefficient coeff_idx at modulus_idx
    pub sk_sss: Vec<ndarray::Array2<u64>>,
    /// Parity check matrices: h[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) × (N_PARTIES + 1)
    /// H * y^T = 0 mod q_j
    pub h: Vec<Vec<Vec<BigUint>>>,
    /// Number of parties
    pub num_parties: usize,
    /// Threshold value
    pub threshold: usize,
}

/// Generate sample secret shares data
///
/// This generates:
/// 1. A random secret (either secret key with trinary coefficients, or smudging noise)
/// 2. Shamir secret shares for each coefficient at each modulus
/// 3. Parity check matrices for each modulus
///
/// # Arguments
///
/// * `trbfv_params` - TRBFV parameters
/// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
/// * `ciphernodes_config` - Optional configuration for number of parties and threshold.
///   If None, uses default values (5 parties, threshold 2).
/// * `lambda` - Security parameter
///
/// # Sample Type
///
/// * `SecretKey` - Generates shares from a secret key (trinary coefficients {-1, 0, 1})
/// * `SmudgingNoise` - Generates shares from smudging noise (actual noise coefficients)
///
/// # Returns
///
/// A `VerifySharesTrbfvData` struct containing the secret coefficients, shares, and parity matrices.
pub fn generate_sample_sk_shares(
    trbfv_params: &Arc<BfvParameters>,
    sample_type: SampleType,
    ciphernodes_config: Option<&CiphernodesConfig>,
    lambda: usize,
) -> Result<VerifySharesTrbfvData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Use provided config or defaults
    let config = ciphernodes_config
        .cloned()
        .unwrap_or_else(CiphernodesConfig::defaults);
    let num_parties = config.num_parties;
    let threshold = config.threshold;

    // Create TRBFV instance for share generation
    let trbfv = TRBFV::new(num_parties, threshold, trbfv_params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    let mut share_manager = ShareManager::new(num_parties, threshold, trbfv_params.clone());

    // Generate shares based on sample type
    let (secret_coeffs, sk_sss) = match sample_type {
        SampleType::SmudgingNoise => {
            // Generate smudging error and split into shares
            let num_ciphertexts = 1;
            let esi_coeffs = trbfv
                .generate_smudging_error(num_ciphertexts, lambda, &mut rng)
                .map_err(|e| format!("Failed to generate smudging error: {:?}", e))?;
            let esi_poly = share_manager
                .bigints_to_poly(&esi_coeffs)
                .map_err(|e| format!("Failed to convert error to poly: {:?}", e))?;
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly.clone(), rng)
                .map_err(|e| format!("Failed to generate error shares: {:?}", e))?;

            // Use smudging noise coefficients directly as the secret
            // The smudging noise coefficients are the actual secret we're sharing
            let secret_coeffs = esi_coeffs.clone();

            (secret_coeffs, esi_sss)
        }
        SampleType::SecretKey => {
            // Generate a random secret key (trinary coefficients)
            let sk = SecretKey::random(trbfv_params, &mut rng);

            // Convert secret key to polynomial
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
                .map_err(|e| format!("Failed to convert SK coeffs to poly: {:?}", e))?;

            // Generate shares for the entire secret key polynomial
            // sk_sss[modulus_idx][party_idx][coeff_idx] gives the share that party_idx has
            // for coefficient coeff_idx at modulus modulus_idx
            let sk_sss = trbfv
                .generate_secret_shares_from_poly(sk_poly.clone(), rng)
                .map_err(|e| format!("Failed to generate SK shares: {:?}", e))?;

            // Extract secret key coefficients (trinary: -1, 0, 1) and convert to BigInt
            let secret_coeffs: Vec<BigInt> = sk.coeffs.iter().map(|&c| BigInt::from(c)).collect();

            (secret_coeffs, sk_sss)
        }
    };

    let num_moduli = trbfv_params.moduli().len();

    // Generate parity check matrices for each modulus
    // H[j] is the parity check matrix for modulus q_j
    // Size: (N_PARTIES - T) × (N_PARTIES + 1)
    let mut h: Vec<Vec<Vec<BigUint>>> = Vec::new();

    for mod_idx in 0..num_moduli {
        let q_j = BigUint::from(trbfv_params.moduli()[mod_idx]);

        // Build generator matrix G for Reed-Solomon code
        // G is (t+1) × (n+1) where t is threshold and n is num_parties
        let config = ParityMatrixConfig {
            q: q_j.clone(),
            t: threshold,
            n: num_parties,
        };

        let g = build_generator_matrix(config)
            .map_err(|e| format!("Failed to build generator matrix: {:?}", e))?;

        // Compute parity check matrix H (null space of G)
        let h_mod =
            null_space(&g, &q_j).map_err(|e| format!("Failed to compute null space: {:?}", e))?;

        // Convert to Vec<Vec<BigUint>> format
        let h_mod_vec: Vec<Vec<BigUint>> = h_mod
            .into_iter()
            .map(|row| row.into_iter().collect())
            .collect();

        h.push(h_mod_vec);
    }

    Ok(VerifySharesTrbfvData {
        secret_coeffs,
        sk_sss,
        h,
        num_parties,
        threshold,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_sample_sk_shares_generation() {
        use shared::circuit::SampleType;

        let trbfv_params = test_parameters_trbfv();

        let result = generate_sample_sk_shares(
            &trbfv_params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        );
        assert!(result.is_ok(), "Sample generation should succeed");

        let data = result.unwrap();
        assert_eq!(data.sk_sss.len(), trbfv_params.moduli().len());
        assert_eq!(data.h.len(), trbfv_params.moduli().len());
    }

    #[test]
    fn test_sample_sk_shares_generation_smudging_noise() {
        use shared::circuit::SampleType;

        let trbfv_params = test_parameters_trbfv();

        let result = generate_sample_sk_shares(
            &trbfv_params,
            SampleType::SmudgingNoise,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        );
        assert!(
            result.is_ok(),
            "Sample generation with smudging noise should succeed"
        );

        let data = result.unwrap();
        assert_eq!(data.sk_sss.len(), trbfv_params.moduli().len());
        assert_eq!(data.h.len(), trbfv_params.moduli().len());
    }
}
