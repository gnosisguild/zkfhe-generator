//! Sample data generation for BFV decryption circuit
//!
//! This module generates sample BFV decryption data needed for the zero-knowledge
//! proof circuit. It simulates the decryption of encrypted Shamir shares.

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_traits::{FheDecrypter, FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use shared::circuit::{CiphernodesConfig, SampleType};
use std::sync::Arc;

/// Data from a sample BFV decryption of encrypted shares
#[derive(Debug, Clone)]
pub struct DecryptionData {
    /// H honest party ciphertexts (multiple encrypted shares from different parties)
    pub honest_ciphertexts: Vec<Ciphertext>,
    /// The sum of all honest ciphertexts (what we're actually decrypting)
    pub sum_ciphertext: Ciphertext,
    /// BFV secret key used for decryption (private witness)
    pub secret_key: SecretKey,
    /// The decrypted message (aggregate share values)
    pub message: Plaintext,
    /// Number of honest parties (H parameter in the circuit)
    pub num_honest_parties: usize,
}

/// Generate a sample BFV decryption with all the data needed for the circuit
///
/// This simulates the decryption phase (stage 5) where a party:
/// 1. Receives encrypted Shamir shares from all parties
/// 2. Homomorphically sums them in encrypted space
/// 3. Decrypts once to get the aggregate key
///
/// # Arguments
///
/// * `bfv_params` - BFV parameters for share encryption
/// * `trbfv_params` - trBFV parameters (for generating realistic share data)
/// * `sample_type` - Type of shares to generate (SecretKey or SmudgingNoise)
/// * `ciphernodes_config` - Optional configuration for number of parties, honest parties, and threshold.
///   If None, uses default values (5 parties, 3 honest parties, threshold 2).
///
/// # Sample Type
///
/// * `SecretKey` - Generates encrypted secret key shares (default use case)
/// * `SmudgingNoise` - Generates encrypted smudging error shares (for noise flooding)
///
/// # Returns
///
/// A `DecryptionData` struct containing the ciphertext, secret key, plaintext,
/// and intermediate decryption values needed for the ZK circuit.
pub fn generate_sample_decryption(
    bfv_params: &Arc<BfvParameters>,
    trbfv_params: &Arc<BfvParameters>,
    sample_type: SampleType,
    ciphernodes_config: Option<&CiphernodesConfig>,
) -> Result<DecryptionData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Use provided config or defaults
    // Default: 5 parties, 3 honest parties, threshold 2
    // This keeps noise within delta_half bound for INSECURE_SET_512_10_1 preset
    // With larger parameter sets, more parties can be supported
    let config = ciphernodes_config
        .cloned()
        .unwrap_or_else(CiphernodesConfig::defaults);
    let num_honest_parties = config.num_honest_parties;
    let threshold = config.threshold;

    // Generate BFV key pair (receiver's keys - party who will decrypt)
    let sk_bfv = SecretKey::random(bfv_params, &mut rng);
    let pk_bfv = PublicKey::new(&sk_bfv, &mut rng);

    // Create TRBFV instance for generating realistic share data
    let trbfv = TRBFV::new(num_honest_parties, threshold, trbfv_params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    let mut share_manager = ShareManager::new(num_honest_parties, threshold, trbfv_params.clone());

    // Generate H honest ciphertexts (one from each party)
    // In practice: each party encrypts their Shamir share and sends it
    let mut honest_ciphertexts = Vec::new();

    for _ in 0..num_honest_parties {
        // Generate share based on sample type
        let share_row = match sample_type {
            SampleType::SmudgingNoise => {
                // Generate smudging error and split into shares
                // This simulates the scenario where parties share noise for smudging
                let num_ciphertexts = 1; // For simplicity in sample generation
                let esi_coeffs = trbfv
                    .generate_smudging_error(num_ciphertexts, &mut rng)
                    .map_err(|e| format!("Failed to generate smudging error: {:?}", e))?;
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs)?;
                let esi_sss = share_manager.generate_secret_shares_from_poly(esi_poly, rng)?;

                // Extract the share that party i sends to the receiver (party 0)
                esi_sss[0].row(0).to_vec()
            }
            SampleType::SecretKey => {
                // Generate a secret key and split it into shares (simulating party i's shares)
                // This is the default scenario: parties share their secret key parts
                let sk = SecretKey::random(trbfv_params, &mut rng);
                let sk_poly = share_manager.coeffs_to_poly_level0(sk.coeffs.clone().as_ref())?;
                let sk_sss = trbfv.generate_secret_shares_from_poly(sk_poly, rng)?;

                // Extract the share that party i sends to the receiver (party 0)
                sk_sss[0].row(0).to_vec()
            }
        };

        // Encrypt this share with BFV using receiver's public key
        let pt = Plaintext::try_encode(&share_row, Encoding::poly(), bfv_params)?;
        let ct = pk_bfv.try_encrypt(&pt, &mut rng)?;

        honest_ciphertexts.push(ct);
    }

    // Compute the sum of all honest ciphertexts (homomorphic addition)
    // sum_ct = ct_1 + ct_2 + ... + ct_H
    let mut sum_ct = honest_ciphertexts[0].clone();
    for ct in honest_ciphertexts.iter().skip(1) {
        sum_ct = &sum_ct + ct;
    }

    // Decrypt the sum to get the aggregate plaintext
    let decrypted_pt = sk_bfv.try_decrypt(&sum_ct)?;

    Ok(DecryptionData {
        honest_ciphertexts,
        sum_ciphertext: sum_ct,
        secret_key: sk_bfv,
        message: decrypted_pt,
        num_honest_parties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters;

    #[test]
    fn test_sample_decryption_generation() {
        let trbfv_params = test_parameters();
        let bfv_params = test_parameters(); // In practice, different params

        // Test with SecretKey sample type
        let result =
            generate_sample_decryption(&bfv_params, &trbfv_params, SampleType::SecretKey, None);
        assert!(result.is_ok(), "Sample generation should succeed");

        let data = result.unwrap();
        assert_eq!(data.sum_ciphertext.level, 0);
        assert_eq!(data.honest_ciphertexts.len(), data.num_honest_parties);
        assert!(data.num_honest_parties > 0);
    }

    #[test]
    fn test_sample_decryption_generation_smudging_noise() {
        let trbfv_params = test_parameters();
        let bfv_params = test_parameters(); // In practice, different params

        // Test with SmudgingNoise sample type
        let result =
            generate_sample_decryption(&bfv_params, &trbfv_params, SampleType::SmudgingNoise, None);
        assert!(
            result.is_ok(),
            "Sample generation with smudging noise should succeed"
        );

        let data = result.unwrap();
        assert_eq!(data.sum_ciphertext.level, 0);
        assert_eq!(data.honest_ciphertexts.len(), data.num_honest_parties);
        assert!(data.num_honest_parties > 0);
    }
}
