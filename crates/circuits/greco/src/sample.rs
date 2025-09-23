use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
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
pub fn generate_sample_encryption(
    params: &Arc<BfvParameters>,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate keys
    let sk = SecretKey::random(params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    // Create a sample plaintext with some random values, in here we are assiging 3 to all the
    // coefficients
    let mut message_data = vec![3u64; params.degree()];

    //For Crisp, the user casts the vote in the right coefficient (message_data[0]). A vote is
    //a value in {0,1}. Any other value will result in a proof that will be rejected by the Verifier.
    message_data[0] = 1;

    let pt = Plaintext::try_encode(&message_data, Encoding::poly(), params)?;

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
