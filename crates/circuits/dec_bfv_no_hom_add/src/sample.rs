//! Sample data generation for BFV decryption circuit (no homomorphic addition)
//!
//! This module generates sample BFV decryption data needed for the zero-knowledge
//! proof circuit. It simulates the decryption of encrypted TRBFV secret key shares.
//!
//! Key differences from dec_bfv:
//! - No homomorphic addition step
//! - H honest parties * L TRBFV bases = H*L ciphertexts (each with L' BFV RNS components)
//! - Each ciphertext is decrypted individually
//! - Final step aggregates decrypted shares per TRBFV basis

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_traits::{FheEncoder, FheEncrypter};
use rand::rngs::OsRng;
use shared::circuit::{CiphernodesConfig, SampleType};
use std::sync::Arc;

/// Data from a sample BFV decryption (no homomorphic addition) of encrypted TRBFV shares
#[derive(Debug, Clone)]
pub struct DecryptionDataNoHomAdd {
    /// H*L ciphertexts (H honest parties, L TRBFV bases)
    /// honest_ciphertexts[party_idx][trbfv_basis]
    pub honest_ciphertexts: Vec<Vec<Ciphertext>>,
    /// BFV secret key used for decryption (private witness)
    pub secret_key: SecretKey,
    /// Decrypted shares for each ciphertext
    /// decrypted_shares[party_idx][trbfv_basis] = plaintext coefficients
    pub decrypted_shares: Vec<Vec<Vec<u64>>>,
    /// Expected aggregated shares per TRBFV basis (sum of decrypted_shares[h][l] for all h)
    /// expected_aggregated_shares[trbfv_basis] = aggregated plaintext coefficients
    pub expected_aggregated_shares: Vec<Vec<u64>>,
    /// Number of honest parties (H parameter in the circuit)
    pub num_honest_parties: usize,
    /// Number of TRBFV bases (L parameter)
    pub num_trbfv_bases: usize,
    /// Number of BFV bases (L' parameter)
    pub num_bfv_bases: usize,
}

/// Generate a sample BFV decryption (no homomorphic addition) with all the data needed for the circuit
///
/// This simulates the decryption phase where a party:
/// 1. Receives H*L encrypted TRBFV secret key shares (H honest parties, L TRBFV bases)
/// 2. Decrypts each ciphertext individually (no homomorphic addition)
/// 3. Aggregates the decrypted shares per TRBFV basis
///
/// # Arguments
///
/// * `bfv_params` - BFV parameters for share encryption/decryption
/// * `trbfv_params` - trBFV parameters (for generating realistic share data)
/// * `sample_type` - The sample type (SecretKey or SmudgingNoise) to determine what type of shares to generate
/// * `ciphernodes_config` - Optional configuration for number of parties, honest parties, and threshold.
///   If None, uses default values (5 parties, 5 honest parties, threshold 2).
/// * `lambda` - The security parameter (λ)
///
/// # Returns
///
/// A `DecryptionDataNoHomAdd` struct containing all ciphertexts, secret key, decrypted shares,
/// and expected aggregated shares needed for the ZK circuit.
pub fn generate_sample_decryption_no_hom_add(
    bfv_params: &Arc<BfvParameters>,
    trbfv_params: &Arc<BfvParameters>,
    sample_type: SampleType,
    ciphernodes_config: Option<&CiphernodesConfig>,
    lambda: usize,
) -> Result<DecryptionDataNoHomAdd, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Use provided config or defaults
    // Default: 5 parties, 5 honest parties, threshold 2 (as per notes.md)
    let config = ciphernodes_config
        .cloned()
        .unwrap_or_else(|| CiphernodesConfig::new(5, 5, 2));
    let num_honest_parties = config.num_honest_parties;
    let threshold = config.threshold;

    // Get number of TRBFV bases (L) and BFV bases (L')
    let num_trbfv_bases = trbfv_params.moduli().len();
    let num_bfv_bases = bfv_params.moduli().len();
    let degree = bfv_params.degree();

    // Generate BFV key pair (receiver's keys - party who will decrypt)
    let sk_bfv = SecretKey::random(bfv_params, &mut rng);
    let pk_bfv = PublicKey::new(&sk_bfv, &mut rng);

    // Create TRBFV instance for generating realistic share data
    let trbfv = TRBFV::new(num_honest_parties, threshold, trbfv_params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    // Generate H*L ciphertexts (one for each party and TRBFV basis)
    let mut honest_ciphertexts: Vec<Vec<Ciphertext>> = Vec::new();
    let mut decrypted_shares: Vec<Vec<Vec<u64>>> = Vec::new();

    for _party_idx in 0..num_honest_parties {
        let mut party_ciphertexts: Vec<Ciphertext> = Vec::new();
        let mut party_decrypted_shares: Vec<Vec<u64>> = Vec::new();

        let mut share_manager =
            ShareManager::new(num_honest_parties, threshold, trbfv_params.clone());

        // Generate shares based on sample type
        let share_rows = match sample_type {
            SampleType::SmudgingNoise => {
                // Generate smudging error and split into shares
                // This simulates the scenario where parties share noise for smudging
                let num_ciphertexts = 1; // For simplicity in sample generation
                let esi_coeffs = trbfv
                    .generate_smudging_error(num_ciphertexts, lambda, &mut rng)
                    .map_err(|e| format!("Failed to generate smudging error: {:?}", e))?;
                let esi_poly = share_manager.bigints_to_poly(&esi_coeffs)?;
                let esi_sss = share_manager.generate_secret_shares_from_poly(esi_poly, rng)?;

                // Extract shares for each TRBFV basis
                // esi_sss is [num_moduli][num_parties][degree]
                esi_sss
                    .iter()
                    .take(num_trbfv_bases)
                    .map(|ss| ss.row(0).to_vec())
                    .collect::<Vec<Vec<u64>>>()
            }
            SampleType::SecretKey => {
                // Generate a secret key for this party and split into shares
                // This is the default scenario: parties share their secret key parts
                let sk = SecretKey::random(trbfv_params, &mut rng);
                let sk_poly = share_manager.coeffs_to_poly_level0(sk.coeffs.clone().as_ref())?;
                let sk_sss = trbfv.generate_secret_shares_from_poly(sk_poly, rng)?;

                // Extract shares for each TRBFV basis
                // sk_sss is [num_moduli][num_parties][degree]
                sk_sss
                    .iter()
                    .take(num_trbfv_bases)
                    .map(|ss| ss.row(0).to_vec())
                    .collect::<Vec<Vec<u64>>>()
            }
        };

        // For each TRBFV basis, encrypt the share for that basis
        for share_row in share_rows {
            // Encrypt this share with BFV using receiver's public key
            let pt = Plaintext::try_encode(&share_row, Encoding::poly(), bfv_params)?;
            let ct = pk_bfv.try_encrypt(&pt, &mut rng)?;

            party_ciphertexts.push(ct);
            party_decrypted_shares.push(share_row);
        }

        honest_ciphertexts.push(party_ciphertexts);
        decrypted_shares.push(party_decrypted_shares);
    }

    // Compute expected aggregated shares per TRBFV basis
    // For each TRBFV basis l: sum of decrypted_shares[h][l] mod trbfv_qis[l]
    let mut expected_aggregated_shares: Vec<Vec<u64>> = Vec::new();

    for trbfv_basis in 0..num_trbfv_bases {
        let trbfv_q = trbfv_params.moduli()[trbfv_basis];
        let mut aggregated: Vec<u64> = vec![0u64; degree];

        for party_shares in decrypted_shares.iter().take(num_honest_parties) {
            for (coeff_idx, coeff) in party_shares[trbfv_basis].iter().enumerate() {
                // Sum and reduce mod TRBFV modulus
                aggregated[coeff_idx] = (aggregated[coeff_idx] + coeff) % trbfv_q;
            }
        }

        expected_aggregated_shares.push(aggregated);
    }

    Ok(DecryptionDataNoHomAdd {
        honest_ciphertexts,
        secret_key: sk_bfv,
        decrypted_shares,
        expected_aggregated_shares,
        num_honest_parties,
        num_trbfv_bases,
        num_bfv_bases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::{test_parameters_bfv, test_parameters_trbfv};

    #[test]
    fn test_sample_decryption_generation() {
        let trbfv_params = test_parameters_trbfv();
        let bfv_params = test_parameters_bfv();

        let result = generate_sample_decryption_no_hom_add(
            &bfv_params,
            &trbfv_params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        );
        assert!(
            result.is_ok(),
            "Sample generation should succeed: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert_eq!(data.honest_ciphertexts.len(), data.num_honest_parties);
        assert_eq!(data.honest_ciphertexts[0].len(), data.num_trbfv_bases);
        assert_eq!(data.decrypted_shares.len(), data.num_honest_parties);
        assert_eq!(data.expected_aggregated_shares.len(), data.num_trbfv_bases);
        assert!(data.num_honest_parties > 0);
    }

    #[test]
    fn test_sample_decryption_with_custom_config() {
        let trbfv_params = test_parameters_trbfv();
        let bfv_params = test_parameters_bfv();

        let config = CiphernodesConfig::new(5, 5, 2);
        let result = generate_sample_decryption_no_hom_add(
            &bfv_params,
            &trbfv_params,
            SampleType::SecretKey,
            Some(&config),
            shared::DEFAULT_INSECURE_LAMBDA,
        );
        assert!(
            result.is_ok(),
            "Sample generation with custom config should succeed: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert_eq!(data.num_honest_parties, 5);
    }
}
