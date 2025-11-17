use fhe::bfv::{BfvParameters, Ciphertext, Encoding, Plaintext, PublicKey};
use fhe::mbfv::{AggregateIter, CommonRandomPoly, PublicKeyShare};
use fhe::trbfv::{ShareManager, TRBFV};
use fhe_math::rq::{Poly, Representation};
use fhe_traits::FheDecoder;
use fhe_traits::{FheEncoder, FheEncrypter};
use ndarray::ArrayView;
use rand::{distributions::Uniform, prelude::Distribution, rngs::OsRng, thread_rng};
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
    let mut thread_rng = thread_rng();

    let num_parties = 5;
    let threshold = 2;
    let num_ciphertexts = 100;

    // Create TRBFV instance for share generation
    let trbfv = TRBFV::new(num_parties, threshold, trbfv_params.clone())
        .map_err(|e| format!("Failed to create TRBFV: {:?}", e))?;

    // Generate a random secret key and create public key shares
    let crp = CommonRandomPoly::new(trbfv_params, &mut thread_rng)
        .map_err(|e| format!("Failed to create CRP: {:?}", e))?;

    // Set up parties: each party generates a secret key and shares
    // Following the pattern from trbfv_add_bfv_share.rs
    struct Party {
        pk_share: PublicKeyShare,
        sk_sss: Vec<ndarray::Array2<u64>>,
        esi_sss: Vec<ndarray::Array2<u64>>,
        sk_sss_collected: Vec<ndarray::Array2<u64>>,
        es_sss_collected: Vec<ndarray::Array2<u64>>,
        sk_poly_sum: Poly,
        es_poly_sum: Poly,
    }

    let mut parties: Vec<Party> = (0..num_parties)
        .map(|_| {
            let mut rng = OsRng;
            let mut rng_thread = rand::thread_rng();

            let sk_share = fhe::bfv::SecretKey::random(trbfv_params, &mut rng);
            let pk_share = PublicKeyShare::new(&sk_share, crp.clone(), &mut rng_thread)
                .map_err(|e| format!("Failed to create public key share: {:?}", e))
                .unwrap();

            let mut share_manager = ShareManager::new(num_parties, threshold, trbfv_params.clone());
            let sk_poly = share_manager
                .coeffs_to_poly_level0(sk_share.coeffs.clone().as_ref())
                .map_err(|e| format!("Failed to convert SK coeffs to poly: {:?}", e))
                .unwrap();

            let temp_trbfv = trbfv.clone();
            let sk_sss = temp_trbfv
                .generate_secret_shares_from_poly(sk_poly, rng)
                .map_err(|e| format!("Failed to generate SK shares: {:?}", e))
                .unwrap();

            let sk_sss_collected: Vec<ndarray::Array2<u64>> = Vec::with_capacity(num_parties);
            let es_sss_collected: Vec<ndarray::Array2<u64>> = Vec::with_capacity(num_parties);
            let sk_poly_sum = Poly::zero(
                trbfv_params.ctx_at_level(0).unwrap(),
                Representation::PowerBasis,
            );
            let es_poly_sum = Poly::zero(
                trbfv_params.ctx_at_level(0).unwrap(),
                Representation::PowerBasis,
            );

            let esi_coeffs = temp_trbfv
                .generate_smudging_error(num_ciphertexts, &mut rng)
                .map_err(|e| format!("Failed to generate smudging error: {:?}", e))
                .unwrap();
            let esi_poly = share_manager
                .bigints_to_poly(&esi_coeffs)
                .map_err(|e| format!("Failed to convert error to poly: {:?}", e))
                .unwrap();
            let esi_sss = share_manager
                .generate_secret_shares_from_poly(esi_poly, rng)
                .map_err(|e| format!("Failed to generate error shares: {:?}", e))
                .unwrap();

            Party {
                pk_share,
                sk_sss,
                esi_sss,
                sk_sss_collected,
                es_sss_collected,
                sk_poly_sum,
                es_poly_sum,
            }
        })
        .collect();

    // Collect shares: each party collects shares from all other parties
    for i in 0..num_parties {
        for j in 0..num_parties {
            let mut node_share_m = ndarray::Array::zeros((0, trbfv_params.degree()));
            let mut es_node_share_m = ndarray::Array::zeros((0, trbfv_params.degree()));
            for m in 0..trbfv_params.moduli().len() {
                node_share_m
                    .push_row(ArrayView::from(&parties[j].sk_sss[m].row(i).clone()))
                    .map_err(|e| format!("Failed to push SK share row: {:?}", e))?;
                es_node_share_m
                    .push_row(ArrayView::from(&parties[j].esi_sss[m].row(i).clone()))
                    .map_err(|e| format!("Failed to push ES share row: {:?}", e))?;
            }
            parties[i].sk_sss_collected.push(node_share_m);
            parties[i].es_sss_collected.push(es_node_share_m);
        }
    }

    // Aggregate collected shares to get sk_poly_sum and es_poly_sum for each party
    for party in parties.iter_mut() {
        let temp_trbfv = trbfv.clone();
        party.sk_poly_sum = temp_trbfv
            .aggregate_collected_shares(&party.sk_sss_collected)
            .map_err(|e| format!("Failed to aggregate SK shares: {:?}", e))?;
        party.es_poly_sum = temp_trbfv
            .aggregate_collected_shares(&party.es_sss_collected)
            .map_err(|e| format!("Failed to aggregate ES shares: {:?}", e))?;
    }

    // Aggregate public key shares to get the full public key
    let public_key: PublicKey = parties
        .iter()
        .map(|p| p.pk_share.clone())
        .collect::<Vec<_>>()
        .iter()
        .cloned()
        .aggregate()
        .map_err(|e| format!("Failed to aggregate public key: {:?}", e))?;

    // Encrypt a sample message (e.g., 1) to create a ciphertext
    let dist = Uniform::new_inclusive(0, 1);
    let numbers: Vec<u64> = dist
        .sample_iter(&mut thread_rng.clone())
        .take(num_ciphertexts)
        .collect();

    let numbers_encrypted: Vec<Ciphertext> = numbers
        .iter()
        .map(|&number| {
            let mut rng = thread_rng.clone();
            let pt = Plaintext::try_encode(&[number], Encoding::poly(), trbfv_params).unwrap();
            public_key.try_encrypt(&pt, &mut rng).unwrap()
        })
        .collect();

    // calculation
    let mut ciphertext = Ciphertext::zero(trbfv_params);
    for ct in &numbers_encrypted {
        ciphertext += ct;
    }
    Arc::new(ciphertext.clone());

    // Generate decryption shares for T+1 parties
    let honest_parties = threshold + 1;
    let mut d_share_polys: Vec<Poly> = Vec::new();

    // For each party, compute their decryption share using already aggregated sk_poly_sum and es_poly_sum
    for party in parties.iter().take(honest_parties) {
        let d_share_rns = trbfv
            .clone()
            .decryption_share(
                Arc::new(ciphertext.clone()),
                party.sk_poly_sum.clone(),
                party.es_poly_sum.clone(),
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
        ciphertext: ciphertext.clone(),
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
