use fhe::bfv::{BfvParameters, PublicKey, SecretKey};
use fhe::mbfv::CommonRandomPoly;
use fhe::mbfv::PublicKeyShare;
use fhe_math::rq::Poly;
use rand::SeedableRng;
use rand::rngs::StdRng;
use shared::circuit::ParameterType;
use std::sync::Arc;

/// Represents either a full public key or a public key share (polynomial).
pub enum PublicKeyOrPoly {
    Full(PublicKey),
    Share(Poly),
}

/// Output structure representing all components involved in a sample BFV encryption.
/// Useful for validating inputs or simulating end-to-end encryption.
pub struct EncryptionData {
    /// The resulting public key `[pk0, pk1]` or just `pk0` share
    pub public_key: PublicKeyOrPoly,
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
    parameter_type: ParameterType,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate a random secret key
    let secret_key = SecretKey::random(params, &mut rng);

    let (public_key, a, sk_rns, e_rns) = if parameter_type == ParameterType::Trbfv {
        let crp = CommonRandomPoly::new(params, &mut rng).unwrap();

        let (public_key_share, a, sk_rns, e_rns) =
            PublicKeyShare::new_extended(&secret_key, crp.clone(), &mut rng).unwrap();

        (PublicKeyOrPoly::Share(public_key_share), a, sk_rns, e_rns)
    } else {
        let (public_key, a, sk_rns, e_rns) =
            PublicKey::new_extended(&secret_key, &mut rng).unwrap();

        (PublicKeyOrPoly::Full(public_key), a, sk_rns, e_rns)
    };

    Ok(EncryptionData {
        public_key,
        a,
        secret_key,
        sk_rns,
        e_rns,
    })
}
