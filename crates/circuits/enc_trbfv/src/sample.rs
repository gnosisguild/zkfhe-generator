use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_math::rq::Poly;
use fhe_traits::FheEncoder;
use rand::{SeedableRng, rngs::StdRng};
use shared::circuit::SampleType;
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
/// Greco proves correct TRBFV encryption operations. This function generates
/// sample encryption data for TRBFV only.
///
/// # Arguments
///
/// * `trbfv_params` - Threshold BFV parameters
/// * `sample_type` - The sample type (SecretKey or SmudgingNoise) - currently unused for TRBFV
/// * `lambda` - The security parameter (λ) - currently unused for TRBFV
///
/// # Notes
///
/// * Greco (Circuit 6) - Encrypt messages/votes using TRBFV
/// * The `sample_type` and `lambda` parameters are kept for API compatibility but not used
pub fn generate_sample_encryption(
    trbfv_params: &Arc<BfvParameters>,
    _sample_type: SampleType,
    _lambda: usize,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate keys for TRBFV
    let sk = SecretKey::random(trbfv_params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    // TRBFV: Encrypt a message/vote (Circuit 6)
    // Create a sample plaintext with some random values, in here we are assigning 3 to all the
    // coefficients
    let mut message_data = vec![3u64; trbfv_params.degree()];

    // For Crisp, the user casts the vote in the right coefficient (message_data[0]). A vote is
    // a value in {0,1}. Any other value will result in a proof that will be rejected by the Verifier.
    message_data[0] = 1;

    let pt = Plaintext::try_encode(&message_data, Encoding::poly(), trbfv_params)?;

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
