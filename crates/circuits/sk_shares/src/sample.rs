//! Sample data generation for secret key shares circuit
//!
//! This module generates a sample secret key using the BFV library,
//! which provides a realistic key for the zero-knowledge proof circuit.

use fhe::bfv::{BfvParameters, SecretKey};
use rand::rngs::OsRng;
use shared::circuit::CiphernodesConfig;
use std::sync::Arc;

/// Data from a sample secret key generation
#[derive(Debug, Clone)]
pub struct SecretKeyShareData {
    /// The secret key being shared
    pub secret_key: SecretKey,
    /// Number of parties receiving shares
    pub num_parties: usize,
    /// Shamir threshold (degree of polynomial)
    pub threshold: usize,
}

/// Generate a sample secret key using BFV
///
/// This generates a realistic BFV secret key that will be used to create
/// Shamir secret shares in the witness generation phase.
///
/// # Arguments
///
/// * `bfv_params` - BFV parameters (used for key dimensions)
/// * `_trbfv_params` - trBFV parameters (unused, kept for API consistency)
/// * `ciphernodes_config` - Optional configuration for number of parties and threshold.
///   If None, uses default values (5 parties, threshold 2).
///
/// # Returns
///
/// A `SecretKeyShareData` struct containing the secret key and configuration parameters.
pub fn generate_sample_sk_shares(
    bfv_params: &Arc<BfvParameters>,
    _trbfv_params: &Arc<BfvParameters>,
    ciphernodes_config: Option<&CiphernodesConfig>,
) -> Result<SecretKeyShareData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Use provided config or defaults
    let config = ciphernodes_config
        .cloned()
        .unwrap_or_else(CiphernodesConfig::defaults);
    let num_parties = config.num_parties;
    let threshold = config.threshold;

    // Generate a secret key using the BFV library
    let secret_key = SecretKey::random(bfv_params, &mut rng);

    Ok(SecretKeyShareData {
        secret_key,
        num_parties,
        threshold,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters;

    #[test]
    fn test_sample_sk_shares_generation() {
        let params = test_parameters();

        let result = generate_sample_sk_shares(&params, &params, None);
        assert!(
            result.is_ok(),
            "Sample generation should succeed: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert!(data.num_parties > 0);
        assert!(data.threshold > 0);
        assert_eq!(
            data.secret_key.coeffs.len(),
            params.degree(),
            "Secret key should have correct degree"
        );
    }

    #[test]
    fn test_sample_sk_shares_with_custom_config() {
        let params = test_parameters();
        let config = CiphernodesConfig {
            num_parties: 7,
            num_honest_parties: 5,
            threshold: 3,
        };

        let result = generate_sample_sk_shares(&params, &params, Some(&config));
        assert!(
            result.is_ok(),
            "Sample generation with custom config should succeed"
        );

        let data = result.unwrap();
        assert_eq!(data.num_parties, 7);
        assert_eq!(data.threshold, 3);
    }
}
