use pvw::PvwParameters;
use pvw::{GlobalPublicKey, Party, PublicKey, PvwCiphertext, PvwCrs, SecretKey};
use rand::{SeedableRng, rngs::StdRng};
use std::sync::Arc;

/// Data from a sample PVW encryption setup
pub struct PvwEncryptionData {
    pub crs: PvwCrs,
    pub parties: Vec<Party>,
    pub global_pk: GlobalPublicKey,
    pub secret_keys: Vec<SecretKey>,
    pub public_keys: Vec<PublicKey>,
    pub error_vectors: Vec<Vec<fhe_math::rq::Poly>>,
    pub ciphertext: Option<PvwCiphertext>,
    pub params: Arc<PvwParameters>,
}

/// Generate a sample PVW encryption setup with all the data needed for circuit input validation
pub fn generate_sample_pvw_data(
    params: &Arc<PvwParameters>,
) -> Result<PvwEncryptionData, Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(0);

    // Generate CRS (Common Reference String)
    let crs = PvwCrs::new(params, &mut rng)?;

    // Initialize global public key with the CRS
    let mut global_pk = GlobalPublicKey::new(crs.clone());

    // Generate parties and their keys
    let mut parties = Vec::new();
    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut error_vectors = Vec::new();
    for i in 0..params.n {
        // Create party with secret key
        let party = Party::new(i, params, &mut rng)?;

        // Generate public key and capture the errors used
        let (public_key, errors) =
            generate_public_key_with_errors(&party.secret_key, &crs, &mut rng)?;

        // Add to global public key matrix
        global_pk.add_public_key(i, public_key.clone())?;

        // Store for later use
        secret_keys.push(party.secret_key.clone());
        public_keys.push(public_key);
        error_vectors.push(errors);
        parties.push(party);
    }
    // Generate a sample ciphertext for demonstrating the PVW encryption
    // This helps in computing r1/r2 quotients if needed
    let sample_values: Vec<u64> = (1..=params.n as u64).collect();
    let sample_ciphertext = if global_pk.is_full() {
        Some(pvw::crypto::encrypt(&sample_values, &global_pk)?)
    } else {
        None
    };
    Ok(PvwEncryptionData {
        crs,
        parties,
        global_pk,
        secret_keys,
        public_keys,
        error_vectors,
        ciphertext: sample_ciphertext,
        params: params.clone(),
    })
}

/// Generate a public key and return both the key and the errors used
/// This replicates the logic from PublicKey::generate but captures the errors
fn generate_public_key_with_errors<R: rand::RngCore + rand::CryptoRng>(
    secret_key: &SecretKey,
    crs: &PvwCrs,
    rng: &mut R,
) -> Result<(PublicKey, Vec<fhe_math::rq::Poly>), Box<dyn std::error::Error>> {
    use pvw::errors::PvwError;

    // Validate dimensions
    if secret_key.params.k != crs.params.k {
        return Err(Box::new(PvwError::DimensionMismatch {
            expected: crs.params.k,
            actual: secret_key.params.k,
        }));
    }

    // Compute A * secret_key using CRS matrix multiplication
    let sk_a_result = crs.multiply_by_secret_key(secret_key)?;

    // Generate error polynomials using the configured error bound
    let mut error_polys = Vec::with_capacity(secret_key.params.k);
    for _ in 0..secret_key.params.k {
        let error_poly = secret_key.params.sample_error_1(rng)?;
        error_polys.push(error_poly);
    }

    // Compute b_i = s_i * A + e_i
    let mut key_polynomials = Vec::with_capacity(secret_key.params.k);
    for (sk_a_poly, error_poly) in sk_a_result.into_iter().zip(error_polys.iter()) {
        let result = &sk_a_poly + error_poly;
        key_polynomials.push(result);
    }

    let public_key = PublicKey {
        key_polynomials,
        params: secret_key.params.clone(),
    };

    Ok((public_key, error_polys))
}
