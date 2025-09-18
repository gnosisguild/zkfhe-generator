use pvw::PvwParameters;
use pvw::{GlobalPublicKey, Party, PvwCiphertext, PvwCrs, encrypt_all_party_shares};
use rand::rngs::OsRng;
use std::sync::Arc;
/// Data from a sample PVW encryption setup
pub struct PvwEncryptionData {
    pub crs: PvwCrs,
    pub parties: Vec<Party>,
    pub global_pk: GlobalPublicKey,
    pub ciphertext: Option<Vec<PvwCiphertext>>,
    pub params: Arc<PvwParameters>,
}

/// Generate a sample PVW encryption setup with all the data needed for circuit input validation
pub fn generate_sample_pvw_data(
    params: &Arc<PvwParameters>,
) -> Result<PvwEncryptionData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;

    // Generate CRS (Common Reference String)
    let crs = PvwCrs::new(params, &mut rng)?;
    // Initialize global public key with the CRS
    let mut global_pk = GlobalPublicKey::new(crs.clone());
    // Generate parties and their keys
    let mut parties = Vec::new();
    for i in 0..params.n {
        let party: Party = Party::new(i, params, &mut rng)?;
        global_pk.generate_and_add_party(&party, &mut rng)?;
        parties.push(party);
    }
    let mut all_party_vectors = Vec::new();
    for party_id in 0..params.n {
        let party_vector: Vec<u64> = (1..=params.n)
            .map(|j| (party_id * 1000 + j) as u64)
            .collect();
        all_party_vectors.push(party_vector);
    }
    let all_ciphertexts = encrypt_all_party_shares(&all_party_vectors, &global_pk)?;
    Ok(PvwEncryptionData {
        crs,
        parties,
        global_pk,
        ciphertext: Some(all_ciphertexts),
        params: params.clone(),
    })
}
