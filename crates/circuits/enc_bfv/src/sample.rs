//! Sample data generation for BFV Encryption circuit
//!
//! This module generates sample encryption data needed for the zero-knowledge
//! proof circuit. It simulates BFV encryption operations.

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use fhe_traits::FheEncoder;
use rand::{SeedableRng, rngs::StdRng};
use shared::circuit::{CiphernodesConfig, SampleType};
use std::sync::Arc;

/// Data from a sample BFV encryption
#[derive(Debug, Clone)]
pub struct EncryptionData {
    pub plaintext: Plaintext,
    pub ciphertext: Ciphertext,
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
    pub u_rns: Poly,
    pub e0_rns: Poly,
    pub e1_rns: Poly,
}

/// Generate a sample encryption with all the data needed for input validation
///
/// enc-bfv proves correct BFV encryption operations. The type of sample data
/// generated depends on the sample type:
///
/// # Arguments
///
/// * `trbfv_params` - Threshold BFV parameters (for secret sharing)
/// * `bfv_params` - Standard BFV parameters (for encryption)
/// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
/// * `ciphernodes_config` - Optional configuration for number of parties and threshold.
///   If None, uses default values (5 parties, threshold 2).
/// * `lambda` - Security parameter
///
/// # Sample Type Usage
///
/// * `SecretKey` (sample_type=SecretKey) - Uses sk_sss share_row (default)
/// * `SmudgingNoise` (sample_type=SmudgingNoise) - Uses es_sss share_row
///
/// # Notes
///
/// enc-bfv only supports BFV parameter type and encrypts threshold shares for distribution.
pub fn generate_sample_encryption(
    trbfv_params: &Arc<BfvParameters>,
    bfv_params: &Arc<BfvParameters>,
    sample_type: SampleType,
    ciphernodes_config: Option<&CiphernodesConfig>,
    lambda: usize,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate keys for trbfv (for secret sharing)
    let sk = SecretKey::random(trbfv_params, &mut rng);

    // Generate keys for bfv (for encryption)
    let sk_bfv = SecretKey::random(bfv_params, &mut rng);
    let pk_bfv = PublicKey::new(&sk_bfv, &mut rng);

    // BFV: Encrypt threshold shares (Circuit 4 - send phase)
    // Use provided config or defaults
    // threshold must be strictly less than num_parties/2
    let config = ciphernodes_config
        .cloned()
        .unwrap_or_else(CiphernodesConfig::defaults);
    let num_parties = config.num_parties;
    let threshold = config.threshold;
    let num_ciphertexts = 10;

    let trbfv = TRBFV::new(num_parties, threshold, trbfv_params.clone())?;
    let mut share_manager = ShareManager::new(num_parties, threshold, trbfv_params.clone());

    // Generate a secret key for secret sharing
    let sk_poly = share_manager.coeffs_to_poly_level0(sk.coeffs.as_ref())?;
    let temp_trbfv = trbfv.clone();

    let share_row = match sample_type {
        SampleType::SmudgingNoise => {
            let esi_coeffs = temp_trbfv
                .generate_smudging_error(num_ciphertexts, lambda, &mut rng)
                .unwrap();
            let esi_poly = share_manager.bigints_to_poly(&esi_coeffs).unwrap();
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly, &mut rng)
                .unwrap();

            // Extract one share (what party j would send to party 0)
            esi_sss[0].row(0).to_vec()
        }
        SampleType::SecretKey => {
            let sk_sss = temp_trbfv
                .generate_secret_shares_from_poly(sk_poly, &mut rng)
                .unwrap();

            // Extract one share (what party j would send to party 0)
            sk_sss[0].row(0).to_vec()
        }
    };

    let pt = Plaintext::try_encode(&share_row, Encoding::poly(), bfv_params)?;

    let (_ct, u_rns, e0_rns, e1_rns) = pk_bfv.try_encrypt_extended(&pt, &mut rng)?;

    Ok(EncryptionData {
        plaintext: pt,
        ciphertext: _ct,
        public_key: pk_bfv,
        secret_key: sk_bfv,
        u_rns,
        e0_rns,
        e1_rns,
    })
}
