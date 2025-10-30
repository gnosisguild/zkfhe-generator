use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe::mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::ArrayView;
use rand::{rngs::OsRng, thread_rng};
use std::sync::Arc;

/// Output structure representing all components involved in a sample decryption share computation.
/// Useful for validating inputs or simulating end-to-end threshold decryption.
pub struct DecryptionShareData {
    /// The ciphertext being decrypted
    pub ciphertext: Ciphertext,
    /// The aggregated sum of shares s = ∑ y_i (in RNS representation)
    pub s_rns: Poly,
    /// The aggregated sum of noise e = ∑ e_i (in RNS representation)
    pub e_rns: Poly,
    /// The computed decryption share d (in RNS representation)
    pub d_share_rns: Poly,
    /// The public key used for encryption (for reference)
    pub public_key: PublicKey,
}

/// Generates a sample decryption share computation setup.
///
/// This simulates a threshold BFV decryption scenario where:
/// - A ciphertext is encrypted under a threshold public key
/// - Aggregated shares s and e are collected from honest parties
/// - A decryption share is computed using TRBFV::decryption_share
///
/// Useful for generating input vectors for zero-knowledge circuits
/// or verifying decryption share computation behavior.
pub fn generate_sample_decryption_share(
    params: &Arc<BfvParameters>,
) -> Result<DecryptionShareData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let mut thread_rng = thread_rng();

    let num_parties = 3;
    let threshold = 1;
    let num_summed = 10;

    // Create TRBFV instance for share generation
    let trbfv = TRBFV::new(num_parties, threshold, params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    // Generate a random secret key and create public key shares
    let crp = CommonRandomPoly::new(params, &mut thread_rng)
        .map_err(|e| format!("Failed to create CRP: {:?}", e))?;

    // Generate secret keys for each party (each party has their own secret key)
    // Each party splits their secret key into shares and sends them to others
    let mut party_secret_keys = Vec::new();
    let mut pk_shares = Vec::new();

    for _ in 0..num_parties {
        let sk = fhe::bfv::SecretKey::random(params, &mut rng);
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut thread_rng)
            .map_err(|e| format!("Failed to create public key share: {:?}", e))?;
        party_secret_keys.push(sk);
        pk_shares.push(pk_share);
    }

    // Aggregate public key shares to get the full public key
    let public_key: PublicKey = pk_shares
        .iter()
        .map(|s| s.clone())
        .aggregate()
        .map_err(|e| format!("Failed to aggregate public key: {:?}", e))?;

    // Encrypt a sample message (e.g., 1) to create a ciphertext
    let message = 1u64;
    let pt = Plaintext::try_encode(&[message], Encoding::poly(), params)?;
    let ciphertext = public_key.try_encrypt(&pt, &mut thread_rng)?;

    // Simulate party 0's perspective:
    // - Each party has their own secret key
    // - Each party splits their secret key into shares and sends them to others
    // - Party 0 collects shares from other parties (including themselves)
    // - When party 0 computes a decryption share, they aggregate all collected shares

    let mut share_manager = ShareManager::new(num_parties, threshold, params.clone());

    // Generate shares for each party's secret key
    // In reality, each party would do this independently
    let mut all_party_sk_shares = Vec::new(); // [party][modulus][receiver][coefficient]
    let mut all_party_esi_shares = Vec::new(); // [party][modulus][receiver][coefficient]

    for party_idx in 0..num_parties {
        let sk = &party_secret_keys[party_idx];
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
            .map_err(|e| format!("Failed to convert SK coeffs to poly: {:?}", e))?;

        let sk_sss = trbfv
            .generate_secret_shares_from_poly(sk_poly, rng)
            .map_err(|e| format!("Failed to generate SK shares: {:?}", e))?;

        all_party_sk_shares.push(sk_sss);

        let esi_coeffs = trbfv
            .generate_smudging_error(num_summed, &mut rng)
            .map_err(|e| format!("Failed to generate smudging error: {:?}", e))?;
        let esi_poly = share_manager
            .bigints_to_poly(&esi_coeffs)
            .map_err(|e| format!("Failed to convert error to poly: {:?}", e))?;
        let esi_sss = share_manager
            .generate_secret_shares_from_poly(esi_poly, rng)
            .map_err(|e| format!("Failed to generate error shares: {:?}", e))?;
        all_party_esi_shares.push(esi_sss);
    }

    // Simulate party 0 collecting shares from other parties
    let honest_parties = threshold + 1;
    let mut sk_sss_collected = Vec::new();
    let mut es_sss_collected = Vec::new();

    for modulus_idx in 0..params.moduli().len() {
        let mut sk_collected = ndarray::Array2::<u64>::zeros((0, params.degree()));
        let mut es_collected = ndarray::Array2::<u64>::zeros((0, params.degree()));

        // Party 0 collects shares from honest parties
        // For each party i, party 0 collects the share that party i sent to party 0
        // This is all_party_sk_shares[i][modulus_idx].row(0) (share for party 0)
        for party_idx in 0..honest_parties {
            // Collect the share that party_idx sent to party 0
            let sk_share_row = all_party_sk_shares[party_idx][modulus_idx].row(0);
            let sk_share_vec = sk_share_row.to_vec();
            sk_collected
                .push_row(ArrayView::from(&sk_share_vec))
                .map_err(|e| format!("Failed to push SK share row: {:?}", e))?;

            let es_share_row = all_party_esi_shares[party_idx][modulus_idx].row(0);
            let es_share_vec = es_share_row.to_vec();
            es_collected
                .push_row(ArrayView::from(&es_share_vec))
                .map_err(|e| format!("Failed to push ES share row: {:?}", e))?;
        }

        sk_sss_collected.push(sk_collected);
        es_sss_collected.push(es_collected);
    }

    // Aggregate collected shares to get s and e polynomials
    let sk_poly_sum = trbfv
        .aggregate_collected_shares(&sk_sss_collected)
        .map_err(|e| format!("Failed to aggregate SK shares: {:?}", e))?;

    let es_poly_sum = trbfv
        .aggregate_collected_shares(&es_sss_collected)
        .map_err(|e| format!("Failed to aggregate ES shares: {:?}", e))?;

    // Compute the decryption share using TRBFV
    let d_share_rns = trbfv
        .clone()
        .decryption_share(
            Arc::new(ciphertext.clone()),
            sk_poly_sum.clone(),
            es_poly_sum.clone(),
        )
        .map_err(|e| format!("Failed to compute decryption share: {:?}", e))?;

    Ok(DecryptionShareData {
        ciphertext,
        s_rns: sk_poly_sum,
        e_rns: es_poly_sum,
        d_share_rns,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::BfvParametersBuilder;
    use num_bigint::BigUint;

    #[test]
    fn generates_sample_decryption_share() {
        let params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .set_variance(10)
            .set_error2_variance(BigUint::from(10u32))
            .build_arc()
            .unwrap();

        let result = generate_sample_decryption_share(&params);
        assert!(
            result.is_ok(),
            "sample generation should succeed: {:?}",
            result.err()
        );
    }
}
