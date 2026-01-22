use fhe::bfv::{BfvParameters, SecretKey};
use fhe::mbfv::CommonRandomPoly;
use fhe::mbfv::PublicKeyShare;
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use rand::SeedableRng;
use rand::rngs::StdRng;
use shared::circuit::CiphernodesConfig;
use std::ops::Deref;
use std::sync::Arc;

/// Output structure representing all components involved in a sample Threshold BFV Public Key encryption.
/// Useful for validating inputs or simulating end-to-end encryption.
pub struct EncryptionData {
    /// The resulting public key `[pk0, pk1]` or just `pk0` share
    pub public_key: Poly,
    /// The secret key used for encryption
    pub secret_key: SecretKey,
    /// The public polynomial `a` used in the public key (pk0 = -a * sk + e)
    pub a: Poly,
    /// The secret key in NTT representation, lifted to RNS
    pub sk_rns: Poly,
    /// The error polynomial `e` used in encryption, in NTT representation
    pub e_rns: Poly,
    /// The smudging noise polynomial (e_sm) for threshold BFV security
    pub e_sm_rns: Poly,
}

/// Generates a sample Threshold BFV Public Key using a random secret key.
///
/// This includes the secret key, encryption polynomial `a = -c1`,
/// the secret key in RNS + NTT domain, the error polynomial, and smudging noise.
///
/// Useful for generating input vectors for zero-knowledge circuits
/// or verifying encryption behavior.
///
/// # Arguments
///
/// * `trbfv_params` - Threshold BFV parameters
/// * `lambda` - Security parameter for smudging noise generation
/// * `ciphernodes_config` - Configuration with num_parties and threshold for smudging bound calculation
/// * `num_ciphertexts` - Number of ciphertexts being processed (for smudging bound calculation)
pub fn generate_sample_encryption(
    trbfv_params: &Arc<BfvParameters>,
    lambda: usize,
    ciphernodes_config: &CiphernodesConfig,
    num_ciphertexts: usize,
) -> Result<EncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate a trbfv secret key
    let secret_key = SecretKey::random(trbfv_params, &mut rng);

    let crp = CommonRandomPoly::new(trbfv_params, &mut rng).unwrap();

    let (public_key_share, a, sk_rns, e_rns) =
        PublicKeyShare::new_extended(&secret_key, crp.clone(), &mut rng).unwrap();

    // Generate smudging noise using TRBFV with config from ciphernodes_config
    let num_parties = ciphernodes_config.num_parties;
    let threshold = ciphernodes_config.threshold;

    let trbfv = TRBFV::new(num_parties, threshold, trbfv_params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    let share_manager = ShareManager::new(num_parties, threshold, trbfv_params.clone());

    // Generate smudging error coefficients
    let esi_coeffs = trbfv
        .generate_smudging_error(num_ciphertexts, lambda, &mut rng)
        .map_err(|e| format!("Failed to generate smudging error: {:?}", e))?;

    // Convert to polynomial in RNS representation
    // bigints_to_poly returns Zeroizing<Poly>, we need to clone the inner Poly
    let e_sm_rns_zeroizing = share_manager
        .bigints_to_poly(&esi_coeffs)
        .map_err(|e| format!("Failed to convert smudging error to poly: {:?}", e))?;
    let e_sm_rns = e_sm_rns_zeroizing.deref().clone();

    Ok(EncryptionData {
        public_key: public_key_share,
        a,
        secret_key,
        sk_rns,
        e_rns,
        e_sm_rns,
    })
}
