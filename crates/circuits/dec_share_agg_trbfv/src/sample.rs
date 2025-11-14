use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe::mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::Poly;
use fhe_traits::FheDecoder;
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::ArrayView;
use rand::{rngs::OsRng, thread_rng};
use std::sync::Arc;

/// Output structure representing all components involved in decryption share aggregation.
/// This includes decryption shares from T+1 parties and the final decrypted message.
#[derive(Debug, Clone)]
pub struct DecryptionShareAggregationData {
    /// The ciphertext being decrypted
    pub ciphertext: Ciphertext,
    /// Decryption shares from T+1 parties (in RNS representation)
    pub d_share_polys: Vec<Poly>,
    /// Party IDs (1-based: 1, 2, ..., T+1)
    pub party_ids: Vec<usize>,
    /// The decoded message
    pub message: Vec<u64>,
    /// Threshold value
    pub threshold: usize,
    /// Number of parties
    pub num_parties: usize,
    /// The public key used for encryption (for reference)
    pub public_key: PublicKey,
}

/// Generates sample decryption share aggregation data.
///
/// This simulates a threshold BFV decryption scenario where:
/// - A ciphertext is encrypted under a threshold public key
/// - T+1 parties each compute their decryption share
/// - The shares are aggregated to recover the plaintext
///
/// Useful for generating input vectors for zero-knowledge circuits
/// or verifying decryption share aggregation behavior.
pub fn generate_sample_decryption_share_aggregation(
    trbfv_params: &Arc<BfvParameters>,
) -> Result<DecryptionShareAggregationData, Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    let mut thread_rng = thread_rng();

    let num_parties = 5;
    let threshold = 2;
    let num_ciphertexts = 10;

    // Create TRBFV instance for share generation
    let trbfv = TRBFV::new(num_parties, threshold, trbfv_params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    // Generate a random secret key and create public key shares
    let crp = CommonRandomPoly::new(trbfv_params, &mut thread_rng)
        .map_err(|e| format!("Failed to create CRP: {:?}", e))?;

    // Generate secret keys for each party (each party has their own secret key)
    // Each party splits their secret key into shares and sends them to others
    let mut party_secret_keys = Vec::new();
    let mut pk_shares = Vec::new();

    for _ in 0..num_parties {
        let sk = fhe::bfv::SecretKey::random(trbfv_params, &mut rng);
        let pk_share = PublicKeyShare::new(&sk, crp.clone(), &mut thread_rng)
            .map_err(|e| format!("Failed to create public key share: {:?}", e))?;
        party_secret_keys.push(sk);
        pk_shares.push(pk_share);
    }

    // Aggregate public key shares to get the full public key
    let public_key: PublicKey = pk_shares
        .iter()
        .cloned()
        .aggregate()
        .map_err(|e| format!("Failed to aggregate public key: {:?}", e))?;

    // Encrypt a sample message (e.g., 1) to create a ciphertext
    let message = 1u64;
    let pt = Plaintext::try_encode(&[message], Encoding::poly(), trbfv_params)?;
    let ciphertext = public_key.try_encrypt(&pt, &mut thread_rng)?;

    let mut share_manager = ShareManager::new(num_parties, threshold, trbfv_params.clone());

    // Generate shares for each party's secret key
    // In reality, each party would do this independently
    let mut all_party_sk_shares = Vec::new(); // [party][modulus][receiver][coefficient]
    let mut all_party_esi_shares = Vec::new(); // [party][modulus][receiver][coefficient]

    for party_sk in party_secret_keys.iter().take(num_parties) {
        let sk = &party_sk;
        let sk_poly = share_manager
            .coeffs_to_poly_level0(sk.coeffs.clone().as_ref())
            .map_err(|e| format!("Failed to convert SK coeffs to poly: {:?}", e))?;

        let sk_sss = trbfv
            .generate_secret_shares_from_poly(sk_poly, rng)
            .map_err(|e| format!("Failed to generate SK shares: {:?}", e))?;

        all_party_sk_shares.push(sk_sss);

        let esi_coeffs = trbfv
            .generate_smudging_error(num_ciphertexts, &mut rng)
            .map_err(|e| format!("Failed to generate smudging error: {:?}", e))?;
        let esi_poly = share_manager
            .bigints_to_poly(&esi_coeffs)
            .map_err(|e| format!("Failed to convert error to poly: {:?}", e))?;
        let esi_sss = share_manager
            .generate_secret_shares_from_poly(esi_poly, rng)
            .map_err(|e| format!("Failed to generate error shares: {:?}", e))?;
        all_party_esi_shares.push(esi_sss);
    }

    // Generate decryption shares for T+1 parties
    let honest_parties = threshold + 1;
    let mut d_share_polys: Vec<Poly> = Vec::new();

    // For each party, collect shares and compute their decryption share
    for party_idx in 0..honest_parties {
        let mut sk_sss_collected = Vec::new();
        let mut es_sss_collected = Vec::new();

        for modulus_idx in 0..trbfv_params.moduli().len() {
            let mut sk_collected = ndarray::Array2::<u64>::zeros((0, trbfv_params.degree()));
            let mut es_collected = ndarray::Array2::<u64>::zeros((0, trbfv_params.degree()));

            // Party party_idx collects shares from honest parties
            // For each sender party i, party party_idx collects the share that party i sent to party party_idx
            for sender_idx in 0..honest_parties {
                // Check bounds before accessing
                if modulus_idx >= all_party_sk_shares[sender_idx].len() {
                    return Err(format!(
                        "Modulus index {} out of bounds for party {} (has {} moduli)",
                        modulus_idx,
                        sender_idx,
                        all_party_sk_shares[sender_idx].len()
                    )
                    .into());
                }
                if modulus_idx >= all_party_esi_shares[sender_idx].len() {
                    return Err(format!(
                        "Modulus index {} out of bounds for party {} error shares (has {} moduli)",
                        modulus_idx,
                        sender_idx,
                        all_party_esi_shares[sender_idx].len()
                    )
                    .into());
                }

                // Collect the share that sender_idx sent to party_idx
                let sk_share_row = all_party_sk_shares[sender_idx][modulus_idx].row(party_idx);
                let sk_share_vec = sk_share_row.to_vec();
                sk_collected
                    .push_row(ArrayView::from(&sk_share_vec))
                    .map_err(|e| format!("Failed to push SK share row: {:?}", e))?;

                let es_share_row = all_party_esi_shares[sender_idx][modulus_idx].row(party_idx);
                let es_share_vec = es_share_row.to_vec();
                es_collected
                    .push_row(ArrayView::from(&es_share_vec))
                    .map_err(|e| format!("Failed to push ES share row: {:?}", e))?;
            }

            sk_sss_collected.push(sk_collected);
            es_sss_collected.push(es_collected);
        }

        // Aggregate collected shares to get s and e polynomials
        let ctx = trbfv_params.ctx_at_level(0)?;
        let num_moduli = sk_sss_collected.len();

        // Sum across parties for each modulus to create [num_moduli, degree] matrices
        let mut sk_sum_matrix = ndarray::Array2::<u64>::zeros((num_moduli, trbfv_params.degree()));
        let mut es_sum_matrix = ndarray::Array2::<u64>::zeros((num_moduli, trbfv_params.degree()));

        for modulus_idx in 0..num_moduli {
            // Sum across parties (rows) for this modulus
            for sender_idx in 0..sk_sss_collected[modulus_idx].nrows() {
                for coeff_idx in 0..trbfv_params.degree() {
                    sk_sum_matrix[[modulus_idx, coeff_idx]] = (sk_sum_matrix
                        [[modulus_idx, coeff_idx]]
                        + sk_sss_collected[modulus_idx][[sender_idx, coeff_idx]])
                        % ctx.moduli()[modulus_idx];
                    es_sum_matrix[[modulus_idx, coeff_idx]] = (es_sum_matrix
                        [[modulus_idx, coeff_idx]]
                        + es_sss_collected[modulus_idx][[sender_idx, coeff_idx]])
                        % ctx.moduli()[modulus_idx];
                }
            }
        }

        // Use aggregate_collected_shares with the correctly formatted data
        let sk_poly_sum = trbfv
            .aggregate_collected_shares(&[sk_sum_matrix])
            .map_err(|e| format!("Failed to aggregate SK shares: {:?}", e))?;

        let es_poly_sum = trbfv
            .aggregate_collected_shares(&[es_sum_matrix])
            .map_err(|e| format!("Failed to aggregate ES shares: {:?}", e))?;

        // Compute the decryption share for this party
        let d_share_rns = trbfv
            .clone()
            .decryption_share(
                Arc::new(ciphertext.clone()),
                sk_poly_sum.clone(),
                es_poly_sum.clone(),
            )
            .map_err(|e| format!("Failed to compute decryption share: {:?}", e))?;

        d_share_polys.push(d_share_rns);
    }

    // Party IDs (1-based: 1, 2, ..., T+1)
    let party_ids: Vec<usize> = (1..=honest_parties).collect();

    // Decrypt to get the message
    let reconstructing_parties: Vec<usize> = (1..=honest_parties).collect();
    let open_results = trbfv
        .decrypt(
            d_share_polys.clone(),
            reconstructing_parties.clone(),
            Arc::new(ciphertext.clone()),
        )
        .map_err(|e| format!("Failed to decrypt: {:?}", e))?;

    let message_vec = Vec::<u64>::try_decode(&open_results, Encoding::poly())
        .map_err(|e| format!("Failed to decode: {:?}", e))?;

    Ok(DecryptionShareAggregationData {
        ciphertext,
        d_share_polys,
        party_ids,
        message: message_vec,
        threshold,
        num_parties,
        public_key,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::BfvParametersBuilder;
    use num_bigint::BigUint;

    #[test]
    fn generates_sample_decryption_share_aggregation() {
        let params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .set_variance(10)
            .set_error1_variance(BigUint::from(10u32))
            .build_arc()
            .unwrap();

        let result = generate_sample_decryption_share_aggregation(&params);
        assert!(
            result.is_ok(),
            "sample generation should succeed: {:?}",
            result.err()
        );

        let data = result.unwrap();
        assert_eq!(data.d_share_polys.len(), data.threshold + 1);
        assert_eq!(data.party_ids.len(), data.threshold + 1);
        assert_eq!(data.party_ids, vec![1, 2, 3]);
    }
}
