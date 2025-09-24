use pvw::PvwParameters;
use pvw::{GlobalPublicKey, Party, PvwCrs};
use rand::rngs::OsRng;
use std::sync::Arc;
/// Data from a sample PVW encryption setup
pub struct PvwEncryptionData {
    pub crs: PvwCrs,
    pub parties: Vec<Party>,
    pub global_pk: GlobalPublicKey,
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
        global_pk.generate_and_add_party_with_errors(&party, &mut rng)?;
        parties.push(party);
    }
    let mut all_party_vectors = Vec::new();
    for party_id in 0..params.n {
        let party_vector: Vec<u64> = (1..=params.n)
            .map(|j| (party_id * 1000 + j) as u64)
            .collect();
        all_party_vectors.push(party_vector);
    }
    Ok(PvwEncryptionData {
        crs,
        parties,
        global_pk,
    })
}
