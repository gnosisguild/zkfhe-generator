use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;

/// Output structure representing all components involved in a sample BFV Public Key.
/// Useful for validating inputs or simulating end-to-end encryption.
pub struct EncryptionData {
    /// The resulting public key `[pk0, pk1]`
    pub public_key: PublicKey,
}

/// Generates a sample BFV Public Key using a random secret key.
///
/// This is used for generating input vectors for zero-knowledge circuits
/// or verifying commitment behavior.
pub fn generate_sample_encryption(
    bfv_params: &Arc<BfvParameters>,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate a BFV secret key
    let secret_key = SecretKey::random(bfv_params, &mut rng);

    // Generate public key (PublicKey::new takes secret_key and rng)
    let public_key = PublicKey::new(&secret_key, &mut rng);

    Ok(EncryptionData { public_key })
}
