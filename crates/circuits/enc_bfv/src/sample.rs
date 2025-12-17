//! Sample data generation for BFV Encryption circuit
//!
//! This module generates sample encryption data needed for the zero-knowledge
//! proof circuit. It simulates BFV encryption operations.

use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey, SecretKey};
use fhe_math::rq::Poly;
use fhe_traits::FheEncoder;
use rand::{SeedableRng, rngs::StdRng};
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
/// # Arguments
///
/// * `bfv_params` - BFV parameters
pub fn generate_sample_encryption(
    bfv_params: &Arc<BfvParameters>,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate keys
    let sk = SecretKey::random(bfv_params, &mut rng);
    let pk = PublicKey::new(&sk, &mut rng);

    // Create a sample plaintext with some random values
    let mut message_data = vec![3u64; bfv_params.degree()];
    message_data[0] = 1;

    let pt = Plaintext::try_encode(&message_data, Encoding::poly(), bfv_params)?;

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
