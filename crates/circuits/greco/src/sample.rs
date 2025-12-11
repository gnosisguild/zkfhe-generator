use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use fhe_traits::FheEncoder;
use rand::{SeedableRng, rngs::StdRng};
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
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
/// Greco proves correct BFV encryption operations. The type of sample data
/// generated depends on the parameter type and sample type:
///
/// # Arguments
///
/// * `trbfv_params` - Threshold BFV parameters
/// * `bfv_params` - Standard BFV parameters
/// * `parameter_type` - The parameter type (BFV or trBFV)
/// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
/// * `ciphernodes_config` - Optional configuration for number of parties, honest parties, and threshold.
///   If None, uses default values (5 parties, 3 honest parties, threshold 2). Only used when parameter_type is BFV.
///
/// # Parameter Type Usage
///
/// * `BFV` (parameter_type=BFV) - Encrypt threshold shares for distribution (Circuit 4)
///   - When `sample_type=SecretKey`: Uses sk_sss share_row (default)
///   - When `sample_type=SmudgingNoise`: Uses es_sss share_row
/// * `trBFV` (parameter_type=Trbfv) - Encrypt messages/votes (Circuit 6)
///
/// # Notes
///
/// * Circuits 1 & 2 (key generation) use the `pktrbfv` circuit
/// * Circuit 5 (decryption proof) uses a custom circuit
/// * The `sample_type` parameter only affects BFV parameter type sample generation
pub fn generate_sample_encryption(
    trbfv_params: &Arc<BfvParameters>,
    bfv_params: &Arc<BfvParameters>,
    parameter_type: ParameterType,
    sample_type: SampleType,
    ciphernodes_config: Option<&CiphernodesConfig>,
    lambda: usize,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate keys trbfv.
    let sk = SecretKey::random(trbfv_params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    // Generate keys bfv.
    let sk_bfv = SecretKey::random(bfv_params, &mut rng);
    let pk_bfv = PublicKey::new(&sk_bfv, &mut rng);

    let pt = if parameter_type == ParameterType::Trbfv {
        // trBFV: Encrypt a message/vote (Circuit 6)
        // Create a sample plaintext with some random values, in here we are assigning 3 to all the
        // coefficients
        let mut message_data = vec![3u64; trbfv_params.degree()];

        // For Crisp, the user casts the vote in the right coefficient (message_data[0]). A vote is
        // a value in {0,1}. Any other value will result in a proof that will be rejected by the Verifier.
        message_data[0] = 1;

        Plaintext::try_encode(&message_data, Encoding::poly(), trbfv_params)?
    } else {
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

        Plaintext::try_encode(&share_row, Encoding::poly(), bfv_params)?
    };

    if parameter_type == ParameterType::Trbfv {
        let (_ct, u_rns, e0_rns, e1_rns) = pk.try_encrypt_extended(&pt, &mut rng)?;

        Ok(EncryptionData {
            plaintext: pt,
            ciphertext: _ct,
            public_key: pk,
            secret_key: sk,
            u_rns,
            e0_rns,
            e1_rns,
        })
    } else {
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
}
