use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use fhe_traits::FheEncoder;
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Data from a sample BFV encryption
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
/// generated depends on the parameter type:
///
/// # Arguments
///
/// * `params` - BFV parameters
/// * `is_threshold` - Whether to use threshold BFV sample data
///
/// # Parameter Type Usage
///
/// * `BFV` (is_threshold=false) - Encrypt threshold shares for distribution (Circuit 4)
/// * `trBFV` (is_threshold=true) - Encrypt messages/votes (Circuit 6)
///
/// # Notes
///
/// * Circuits 1 & 2 (key generation) use the `pktrbfv` circuit
/// * Circuit 5 (decryption proof) uses a custom circuit
pub fn generate_sample_encryption(
    params: &Arc<BfvParameters>,
    is_threshold: bool,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate keys
    let sk = SecretKey::random(params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    let pt = if is_threshold {
        // trBFV: Encrypt a message/vote (Circuit 6)
        // Create a sample plaintext with some random values, in here we are assigning 3 to all the
        // coefficients
        let mut message_data = vec![3u64; params.degree()];

        // For Crisp, the user casts the vote in the right coefficient (message_data[0]). A vote is
        // a value in {0,1}. Any other value will result in a proof that will be rejected by the Verifier.
        message_data[0] = 1;

        Plaintext::try_encode(&message_data, Encoding::poly(), params)?
    } else {
        // BFV: Encrypt threshold shares (Circuit 4 - send phase)

        // Default threshold params for sample generation
        // threshold must be strictly less than num_parties/2
        let num_parties = 3;
        let threshold = 1;

        let trbfv = TRBFV::new(num_parties, threshold, params.clone())?;
        let share_manager = ShareManager::new(num_parties, threshold, params.clone());

        // Generate a secret key and create shares of it
        let sample_sk = SecretKey::random(params, &mut rng);
        let sk_poly = share_manager.coeffs_to_poly_level0(sample_sk.coeffs.as_ref())?;
        let temp_trbfv = trbfv.clone();
        let sk_sss = temp_trbfv
            .generate_secret_shares_from_poly(sk_poly, &mut rng)
            .unwrap();

        // Extract one share (what party j would send to party 0)
        let share_row = sk_sss[0].row(0).to_vec();

        Plaintext::try_encode(&share_row, Encoding::poly(), params)?
    };

    // Use extended encryption to get the polynomial data
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
}
