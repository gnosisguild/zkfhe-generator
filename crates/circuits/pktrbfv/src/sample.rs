use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use fhe_math::rq::Poly;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::sync::Arc;

/// Output structure representing all components involved in a sample BFV encryption.
/// Useful for validating inputs or simulating end-to-end encryption.
pub struct EncryptionData {
    /// The resulting public key `[pk0, pk1]`
    pub public_key: PublicKey,
    /// The secret key used for encryption
    pub secret_key: SecretKey,
    /// The public polynomial `a` used in the public key (pk0 = -a * sk + e)
    pub a: Poly,
    /// The secret key in NTT representation, lifted to RNS
    pub sk_rns: Poly,
    /// The error polynomial `e` used in encryption, in NTT representation
    pub e_rns: Poly,
}

/// Generates a sample public key using a random secret key.
///
/// This includes the secret key, encryption polynomial `a = -c1`,
/// the secret key in RNS + NTT domain, and the error polynomial.
///
/// Useful for generating input vectors for zero-knowledge circuits
/// or verifying encryption behavior.
pub fn generate_sample_encryption(
    params: &Arc<BfvParameters>,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate a random secret key
    let secret_key = SecretKey::random(&params, &mut rng);

    // Perform encryption and extract intermediate values (a, sk, e)
    let (public_key, a, sk_rns, e_rns) = PublicKey::new_extended(&secret_key, &mut rng)?;

    Ok(EncryptionData {
        public_key,
        a,
        secret_key,
        sk_rns,
        e_rns,
    })
}
