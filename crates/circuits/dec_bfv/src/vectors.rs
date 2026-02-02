//! Input validation vectors for BFV decryption zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct BFV decryption in zero-knowledge.

use fhe::bfv::{BfvParameters, Ciphertext, SecretKey};
use fhe_traits::FheDecrypter;
use num_bigint::BigInt;
use num_traits::Zero;
use serde_json::json;
use shared::commitments::compute_share_encryption_commitment_from_message;
use shared::errors::{ZkFheError, ZkFheResult};
use shared::utils::to_string_1d_vec;
use std::sync::Arc;
/// Set of vectors for input validation of BFV decryption
/// Structure matches bfv_dec.nr circuit:
/// - expected_commitments[H][L]: Expected commitments from Circuit 3 for H honest parties
/// - decrypted_shares[H][L][N]: Decrypted shares from H honest parties
#[derive(Clone, Debug)]
pub struct DecBfvVectors {
    /// Expected commitments from Circuit 3 for H honest parties: [party_idx][mod_idx]
    pub expected_commitments: Vec<Vec<BigInt>>, // [H][L]
    /// Decrypted shares from H honest parties: [party_idx][mod_idx][coeff_idx]
    pub decrypted_shares: Vec<Vec<Vec<BigInt>>>, // [H][L][N]
}

impl DecBfvVectors {
    /// Create a new `DecBfvVectors` with the given dimensions
    pub fn new(num_honest_parties: usize, num_trbfv_bases: usize, degree: usize) -> Self {
        DecBfvVectors {
            expected_commitments: vec![vec![BigInt::zero(); num_trbfv_bases]; num_honest_parties],
            decrypted_shares: vec![
                vec![vec![BigInt::zero(); degree]; num_trbfv_bases];
                num_honest_parties
            ],
        }
    }

    /// Create the validation vectors for BFV decryption proof.
    ///
    /// This computes:
    /// 1. Decrypts each ciphertext to get the decrypted share
    /// 2. Computes expected commitment for each decrypted share (from Circuit 3)
    ///
    /// # Arguments
    ///
    /// * `honest_cts` - H*L ciphertexts [party_idx][trbfv_basis]
    /// * `sk` - BFV secret key used for decryption
    /// * `bfv_params` - BFV parameters
    /// * `trbfv_params` - TRBFV parameters (for L)
    /// * `bit_msg` - Bit width for message (for commitment computation)
    pub fn compute(
        honest_cts: &[Vec<Ciphertext>],
        sk: &SecretKey,
        bfv_params: &Arc<BfvParameters>,
        trbfv_params: &Arc<BfvParameters>,
        bit_msg: u32,
    ) -> ZkFheResult<DecBfvVectors> {
        let num_honest_parties = honest_cts.len();
        let num_trbfv_bases = trbfv_params.moduli().len();
        let degree = bfv_params.degree();

        // Initialize result structure
        let mut res = DecBfvVectors::new(num_honest_parties, num_trbfv_bases, degree);

        // Decrypt each ciphertext and compute its commitment
        for (party_idx, party_cts) in honest_cts.iter().enumerate() {
            for mod_idx in 0..num_trbfv_bases {
                if mod_idx < party_cts.len() {
                    // Decrypt the ciphertext to get the plaintext share
                    let decrypted_pt =
                        sk.try_decrypt(&party_cts[mod_idx])
                            .map_err(|e| ZkFheError::Bfv {
                                message: format!("Failed to decrypt ciphertext: {:?}", e),
                            })?;

                    // Extract decrypted share coefficients
                    // Plaintext coefficients are in [0, t), reverse them for polynomial representation
                    let share_coeffs: Vec<BigInt> = decrypted_pt
                        .value
                        .iter()
                        .map(|&x| BigInt::from(x))
                        .rev()
                        .collect();

                    res.decrypted_shares[party_idx][mod_idx] = share_coeffs.clone();

                    // Compute expected commitment for this decrypted share
                    // This matches Circuit 3's message commitment
                    res.expected_commitments[party_idx][mod_idx] =
                        compute_share_encryption_commitment_from_message(&share_coeffs, bit_msg);
                }
            }
        }

        Ok(res)
    }

    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();

        // Helper function to reduce 3D vectors
        fn reduce_coefficients_3d(
            vec: &[Vec<Vec<BigInt>>],
            zkp_modulus: &BigInt,
        ) -> Vec<Vec<Vec<BigInt>>> {
            vec.iter()
                .map(|d1| {
                    d1.iter()
                        .map(|d2| {
                            d2.iter()
                                .map(|x| {
                                    let mut reduced = x.clone() % zkp_modulus;
                                    if reduced < BigInt::zero() {
                                        reduced += zkp_modulus;
                                    }
                                    reduced
                                })
                                .collect()
                        })
                        .collect()
                })
                .collect()
        }

        // Helper function to reduce 2D vectors
        fn reduce_coefficients_2d(vec: &[Vec<BigInt>], zkp_modulus: &BigInt) -> Vec<Vec<BigInt>> {
            vec.iter()
                .map(|d1| {
                    d1.iter()
                        .map(|x| {
                            let mut reduced = x.clone() % zkp_modulus;
                            if reduced < BigInt::zero() {
                                reduced += zkp_modulus;
                            }
                            reduced
                        })
                        .collect()
                })
                .collect()
        }

        DecBfvVectors {
            expected_commitments: reduce_coefficients_2d(&self.expected_commitments, zkp_modulus),
            decrypted_shares: reduce_coefficients_3d(&self.decrypted_shares, zkp_modulus),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        use shared::utils::to_string_2d_vec;
        json!({
            "expected_commitments": to_string_2d_vec(&self.expected_commitments),
            "decrypted_shares": self.decrypted_shares.iter().map(|party_shares| {
                party_shares.iter().map(|share| {
                    json!({
                        "coefficients": to_string_1d_vec(share)
                    })
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_decryption;
    use shared::circuit::SampleType;
    use shared::utils::{test_parameters_bfv, test_parameters_trbfv};

    #[test]
    fn test_vector_computation() {
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();
        let data = generate_sample_decryption(
            &bfv_params,
            &trbfv_params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        // Use the honest_ciphertexts directly
        let honest_cts: &[Vec<Ciphertext>] = &data.honest_ciphertexts;

        // Calculate bit_msg for commitment computation
        let bit_msg = 8; // Reasonable default for plaintext modulus

        let vectors = DecBfvVectors::compute(
            honest_cts,
            &data.secret_key,
            &bfv_params,
            &trbfv_params,
            bit_msg,
        )
        .unwrap();

        // Verify structure
        assert_eq!(vectors.expected_commitments.len(), data.num_honest_parties);
        assert_eq!(vectors.decrypted_shares.len(), data.num_honest_parties);
        if !vectors.decrypted_shares.is_empty() {
            assert_eq!(
                vectors.decrypted_shares[0].len(),
                trbfv_params.moduli().len()
            );
        }
    }

    #[test]
    fn test_standard_form() {
        let vecs = DecBfvVectors::new(3, 2, 512); // H=3, L=2, N=512
        let std_form = vecs.standard_form();

        // Check that all vectors are properly reduced
        let p = shared::constants::get_zkp_modulus();
        for party_commitments in &std_form.expected_commitments {
            assert!(party_commitments.iter().all(|x| x < &p));
        }
        for party_shares in &std_form.decrypted_shares {
            for share in party_shares {
                assert!(share.iter().all(|x| x < &p));
            }
        }
    }
}
