use fhe::bfv::{BfvParameters, PublicKey};
use fhe::mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare};
use fhe_math::rq::Poly;
use rand::{rngs::OsRng, thread_rng};
use shared::circuit::CiphernodesConfig;
use std::sync::Arc;

/// Data from a sample public key aggregation
#[derive(Debug, Clone)]
pub struct PkAggTrBfvData {
    /// Public key shares from honest parties: pk0_shares[party_idx] is the pk0 share (Poly)
    pub pk0_shares: Vec<Poly>,
    /// Common random polynomial (used as pk1 for all shares)
    pub a: Poly,
    /// Aggregated public key
    pub public_key: PublicKey,
    /// Number of honest parties
    pub num_honest_parties: usize,
}

/// Generate sample public key aggregation data
///
/// This generates:
/// 1. Public key shares from H honest parties
/// 2. Aggregated public key from those shares
///
/// # Arguments
///
/// * `trbfv_params` - TRBFV parameters
/// * `ciphernodes_config` - Optional configuration for number of honest parties.
///   If None, uses default values (3 honest parties).
pub fn generate_sample_pk_aggregation(
    trbfv_params: &Arc<BfvParameters>,
    ciphernodes_config: Option<&CiphernodesConfig>,
) -> Result<PkAggTrBfvData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let mut thread_rng = thread_rng();

    // Use provided config or defaults
    let config = ciphernodes_config
        .cloned()
        .unwrap_or_else(CiphernodesConfig::defaults);
    let num_honest_parties = config.num_honest_parties;

    // Create common random polynomial (shared across all parties)
    let crp = CommonRandomPoly::new(trbfv_params, &mut rng)
        .map_err(|e| format!("Failed to create CRP: {:?}", e))?;

    // Get the common random polynomial (a) - same for all parties
    // This is pk1 for all shares
    let a_poly = crp.poly().clone();

    // Generate public key shares for each party
    let mut pk_shares = Vec::new();
    let mut pk0_shares = Vec::new();

    for _ in 0..num_honest_parties {
        let sk = fhe::bfv::SecretKey::random(trbfv_params, &mut rng);
        // Create PublicKeyShare - this generates the p0_share with a specific error term
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut thread_rng)
            .map_err(|e| format!("Failed to create public key share: {:?}", e))?;

        // Extract the p0_share Poly from the PublicKeyShare
        // This ensures we use the same error term for both aggregation and vector extraction
        let pk0_share = pk_share.p0_share().clone();

        pk_shares.push(pk_share);
        pk0_shares.push(pk0_share);
    }

    // Aggregate public key shares to get the full public key
    let public_key: PublicKey = pk_shares
        .iter()
        .cloned()
        .aggregate()
        .map_err(|e| format!("Failed to aggregate public key: {:?}", e))?;

    Ok(PkAggTrBfvData {
        pk0_shares,
        a: a_poly,
        public_key,
        num_honest_parties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_sample_pk_aggregation_generation() {
        let trbfv_params = test_parameters_trbfv();

        let result = generate_sample_pk_aggregation(&trbfv_params, None);
        assert!(result.is_ok(), "Sample generation should succeed");

        let data = result.unwrap();
        assert_eq!(data.pk0_shares.len(), data.num_honest_parties);
    }
}
