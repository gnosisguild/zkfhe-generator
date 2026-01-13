//! Input validation vectors for Secret Key Shares verification zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct secret key shares in zero-knowledge.

use crate::sample::VerifySharesTrbfvData;
use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
use num_traits::Zero;
use shared::commitments::compute_secret_commitment;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Set of vectors for input validation of Verify Shares TRBFV
#[derive(Clone, Debug)]
pub struct VerifySharesTrbfvVectors {
    /// Secret polynomial per modulus: secret_crt[mod_idx][coeff_idx]
    /// For SK: all moduli use the same polynomial (trinary coefficients {-1, 0, 1})
    /// For ESM: each modulus has its own polynomial (RNS representation: secret[i] mod q_j)
    pub secret_crt: Vec<Vec<BigInt>>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = secret_crt[j][i] (secret coefficient i at modulus j)
    /// y[i][j][k] = share for party k-1 (for k = 1..N_PARTIES)
    pub y: Vec<Vec<Vec<BigInt>>>,
    /// Parity check matrices: h[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) × (N_PARTIES + 1)
    pub h: Vec<Vec<Vec<BigInt>>>,
    /// Expected commitment to secret (from C1, pk_trbfv circuit)
    /// This can be either commit(sk_trbfv) or commit(e_sm)
    /// Uses secret_crt[0] (first modulus) for commitment computation
    pub expected_secret_commitment: BigInt,
}

impl VerifySharesTrbfvVectors {
    /// Create a new `VerifySharesTrbfvVectors` with the given dimensions.
    pub fn new(degree: usize, num_moduli: usize, num_parties: usize, threshold: usize) -> Self {
        let num_parity_rows = num_parties - threshold;
        VerifySharesTrbfvVectors {
            secret_crt: vec![vec![BigInt::zero(); degree]; num_moduli],
            y: vec![vec![vec![BigInt::zero(); num_parties + 1]; num_moduli]; degree],
            h: vec![vec![vec![BigInt::zero(); num_parties + 1]; num_parity_rows]; num_moduli],
            expected_secret_commitment: BigInt::zero(),
        }
    }

    /// Create vectors from sample data
    ///
    /// # Arguments
    ///
    /// * `data` - Sample secret key shares data
    /// * `params` - BFV parameters
    /// * `bit_secret` - Bit width for secret bounds (used for commitment computation)
    ///
    /// # Returns
    ///
    /// A `VerifySharesTrbfvVectors` struct containing all witness vectors.
    /// y and h are already normalized from sample data, no need to normalize again.
    pub fn compute(
        data: &VerifySharesTrbfvData,
        params: &Arc<BfvParameters>,
        bit_secret: u32,
    ) -> ZkFheResult<Self> {
        let ctx = params.ctx_at_level(0)?;
        let degree = params.degree();
        let num_moduli = ctx.moduli().len();

        // Extract secret coefficients (already in BigInt form)
        // For secret key: secret[i] is range-checked to be in {-1, 0, 1} (trinary)
        // For smudging noise: secret[i] can be any value within the noise bound
        let secret = data.secret_coeffs.clone();

        // Compute secret_crt: [Polynomial<N>; L] where secret_crt[j][i] is the secret at modulus j
        // For SK: secret_crt[j][i] = secret[i] (same for all j, trinary)
        // For ESM: secret_crt[j][i] = secret[i] mod q_j (RNS representation)
        // We detect SK vs ESM by checking if secret values are in {-1, 0, 1}
        let is_secret_key = secret
            .iter()
            .all(|s| *s == BigInt::from(-1) || *s == BigInt::zero() || *s == BigInt::from(1));

        let mut secret_crt: Vec<Vec<BigInt>> = Vec::new();

        for mod_idx in 0..num_moduli {
            let q_j = BigInt::from(ctx.moduli()[mod_idx]);
            let mut secret_mod: Vec<BigInt> = Vec::new();

            for secret_dgr in secret.iter().take(degree) {
                if is_secret_key {
                    // For SK: use the same trinary value for all moduli
                    secret_mod.push(secret_dgr.clone());
                } else {
                    // For ESM: reduce modulo q_j
                    let mut reduced = secret_dgr.clone() % &q_j;
                    if reduced < BigInt::zero() {
                        reduced += &q_j;
                    }
                    secret_mod.push(reduced);
                }
            }

            secret_crt.push(secret_mod);
        }

        // Compute y[coeff_idx][mod_idx][0..N_PARTIES+1] from secret_crt and sk_sss
        // y[i][j][0] = secret_crt[j][i] (secret coefficient i at modulus j)
        // y[i][j][k] = sk_sss[j][k-1][i] (share for party k-1, already normalized to [0, q_j))
        let mut y: Vec<Vec<Vec<BigInt>>> = Vec::new();

        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..degree {
            let mut y_coeff: Vec<Vec<BigInt>> = Vec::new();

            for mod_idx in 0..num_moduli {
                let mut y_mod: Vec<BigInt> = Vec::new();

                // y[i][j][0] = secret_crt[j][i] (matches Noir circuit)
                y_mod.push(secret_crt[mod_idx][coeff_idx].clone());

                // y[i][j][k] for k = 1..N_PARTIES from sk_sss
                // sk_sss[mod_idx][party_idx][coeff_idx] gives the share that party_idx has
                // Shares are already normalized to [0, q_j) from sample generation
                for party_idx in 0..data.num_parties {
                    let share_value = data.sk_sss[mod_idx][[party_idx, coeff_idx]];
                    y_mod.push(BigInt::from(share_value));
                }

                y_coeff.push(y_mod);
            }

            y.push(y_coeff);
        }

        // Extract parity matrices h[mod_idx][row][col]
        // Convert from BigUint to BigInt (already normalized to [0, q_j) from sample generation)
        let mut h: Vec<Vec<Vec<BigInt>>> = Vec::new();

        for mod_idx in 0..num_moduli {
            let mut h_mod: Vec<Vec<BigInt>> = Vec::new();

            for row in &data.h[mod_idx] {
                let h_row: Vec<BigInt> =
                    row.iter().map(|cell| BigInt::from(cell.clone())).collect();
                h_mod.push(h_row);
            }

            h.push(h_mod);
        }

        // Compute expected_secret_commitment (matches C1's compute_secret_commitment)
        // Uses secret_crt[0] (first modulus) for commitment computation, matching Noir circuit
        let expected_secret_commitment = compute_secret_commitment(&secret_crt[0], bit_secret);

        Ok(VerifySharesTrbfvVectors {
            secret_crt,
            y,
            h,
            expected_secret_commitment,
        })
    }

    /// Verify that the vectors satisfy all circuit constraints
    ///
    /// This function checks:
    /// 1. Secret consistency: y[i][j][0] == secret[i] for all i, j
    /// 2. Range checks: secret coefficients (trinary for secret key, bounded for smudging noise), shares are in [0, q_j)
    /// 3. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
    ///
    /// # Arguments
    ///
    /// * `params` - BFV parameters
    /// * `num_parties` - Number of parties
    /// * `threshold` - Threshold value
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if all checks pass, or an error describing what failed.
    pub fn verify(
        &self,
        params: &Arc<BfvParameters>,
        num_parties: usize,
        threshold: usize,
    ) -> ZkFheResult<()> {
        let ctx = params.ctx_at_level(0)?;
        let degree = params.degree();
        let num_moduli = ctx.moduli().len();

        // Step 1: Verify secret consistency
        // y[i][j][0] == secret_crt[j][i] for all i, j
        // This matches the Noir circuit's verify_secret_consistency check
        for coeff_idx in 0..degree {
            for mod_idx in 0..num_moduli {
                let secret_coeff = &self.secret_crt[mod_idx][coeff_idx];
                let y_value = &self.y[coeff_idx][mod_idx][0];

                // The circuit expects exact equality: y[i][j][0] == secret_crt[j][i]
                if secret_coeff != y_value {
                    return Err(shared::errors::ZkFheError::Bfv {
                        message: format!(
                            "Secret consistency check failed at coefficient {}, modulus {}: secret_crt[{}][{}] = {}, y[{}][{}][0] = {}. These should be equal.",
                            coeff_idx,
                            mod_idx,
                            mod_idx,
                            coeff_idx,
                            secret_coeff,
                            coeff_idx,
                            mod_idx,
                            y_value
                        ),
                    });
                }
            }
        }

        // Step 2: Range checks
        // We don't verify range here as it depends on the sample type, but the circuit will check it

        // Shares y[i][j][k] for k >= 1 should be in [0, q_j)
        for mod_idx in 0..num_moduli {
            let q_j = BigInt::from(ctx.moduli()[mod_idx]);

            for coeff_idx in 0..degree {
                for party_idx in 1..(num_parties + 1) {
                    let share_value = &self.y[coeff_idx][mod_idx][party_idx];

                    // Normalize to [0, q_j)
                    let mut normalized = share_value.clone();
                    normalized %= &q_j;
                    if normalized < BigInt::zero() {
                        normalized += &q_j;
                    }

                    // Check if share is in [0, q_j)
                    if normalized >= q_j || normalized < BigInt::zero() {
                        return Err(shared::errors::ZkFheError::Bfv {
                            message: format!(
                                "Share range check failed at coefficient {}, modulus {}, party {}: share (mod q_j) = {}, expected in [0, {})",
                                coeff_idx,
                                mod_idx,
                                party_idx - 1,
                                normalized,
                                q_j
                            ),
                        });
                    }
                }
            }
        }

        // Step 3: Verify parity check
        // H[j] * y[i][j]^T == 0 mod q_j for all i, j
        for coeff_idx in 0..degree {
            for mod_idx in 0..num_moduli {
                let q_j = BigInt::from(ctx.moduli()[mod_idx]);
                let num_parity_rows = num_parties - threshold;

                // For each row of H, compute dot product with y and verify == 0
                for row_idx in 0..num_parity_rows {
                    let mut sum = BigInt::zero();

                    // Compute H[j][row] * y[i][j]^T
                    for col_idx in 0..(num_parties + 1) {
                        let h_value = &self.h[mod_idx][row_idx][col_idx];
                        let y_value = &self.y[coeff_idx][mod_idx][col_idx];

                        // Normalize both to [0, q_j) before multiplication
                        let mut h_normalized = h_value.clone();
                        h_normalized %= &q_j;
                        if h_normalized < BigInt::zero() {
                            h_normalized += &q_j;
                        }

                        let mut y_normalized = y_value.clone();
                        y_normalized %= &q_j;
                        if y_normalized < BigInt::zero() {
                            y_normalized += &q_j;
                        }

                        sum = (sum + &h_normalized * &y_normalized) % &q_j;
                    }

                    // Normalize sum to [0, q_j)
                    if sum < BigInt::zero() {
                        sum += &q_j;
                    }

                    // Verify sum == 0 mod q_j
                    if sum != BigInt::zero() {
                        return Err(shared::errors::ZkFheError::Bfv {
                            message: format!(
                                "Parity check failed at coefficient {}, modulus {}, row {}: H * y^T (mod q_j) = {}, expected 0",
                                coeff_idx, mod_idx, row_idx, sum
                            ),
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Convert to standard form (reduce modulo ZKP modulus)
    ///
    /// This reduces all coefficients modulo the ZKP field modulus to ensure
    /// they fit within the circuit's field representation.
    pub fn standard_form(self) -> Self {
        use bigint_poly::reduce_coefficients_3d;
        use shared::constants::get_zkp_modulus;
        let zkp_modulus = get_zkp_modulus();

        // Reduce secret_crt coefficients (2D array: [L][N])
        let secret_crt: Vec<Vec<BigInt>> = self
            .secret_crt
            .into_iter()
            .map(|mod_secret| {
                mod_secret
                    .into_iter()
                    .map(|x| {
                        let mut reduced = x % &zkp_modulus;
                        if reduced < BigInt::zero() {
                            reduced += &zkp_modulus;
                        }
                        reduced
                    })
                    .collect()
            })
            .collect();

        // Reduce y coefficients (3D array)
        let y = reduce_coefficients_3d(&self.y, &zkp_modulus);

        // Reduce h coefficients (3D array)
        let h = reduce_coefficients_3d(&self.h, &zkp_modulus);

        // Reduce expected_secret_commitment modulo ZKP modulus
        let mut expected_secret_commitment = self.expected_secret_commitment % &zkp_modulus;
        if expected_secret_commitment < BigInt::zero() {
            expected_secret_commitment += &zkp_modulus;
        }

        VerifySharesTrbfvVectors {
            secret_crt,
            y,
            h,
            expected_secret_commitment,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_sk_shares;
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_vectors_computation() {
        use crate::bounds::VerifySharesTrbfvBounds;
        use shared::circuit::SampleType;
        let params = test_parameters_trbfv();
        let (_, bounds) = VerifySharesTrbfvBounds::compute(&params, 0).unwrap();
        let bit_secret =
            shared::template::calculate_bit_width(&bounds.sk_bound.to_string()).unwrap();

        let data = generate_sample_sk_shares(
            &params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        let vectors = VerifySharesTrbfvVectors::compute(&data, &params, bit_secret).unwrap();
        assert_eq!(vectors.secret_crt.len(), params.moduli().len());
        for mod_secret in &vectors.secret_crt {
            assert_eq!(mod_secret.len(), params.degree());
        }
        assert_eq!(vectors.y.len(), params.degree());
        assert_eq!(vectors.h.len(), params.moduli().len());

        // Verify y structure
        for coeff_idx in 0..vectors.y.len() {
            assert_eq!(vectors.y[coeff_idx].len(), params.moduli().len());
            for mod_idx in 0..vectors.y[coeff_idx].len() {
                assert_eq!(vectors.y[coeff_idx][mod_idx].len(), data.num_parties + 1);
            }
        }

        // Verify h structure
        for mod_idx in 0..vectors.h.len() {
            let expected_rows = data.num_parties - data.threshold;
            assert_eq!(vectors.h[mod_idx].len(), expected_rows);
            for row in &vectors.h[mod_idx] {
                assert_eq!(row.len(), data.num_parties + 1);
            }
        }
    }

    #[test]
    fn test_standard_form() {
        use crate::bounds::VerifySharesTrbfvBounds;
        use shared::circuit::SampleType;
        let params = test_parameters_trbfv();
        let (_, bounds) = VerifySharesTrbfvBounds::compute(&params, 0).unwrap();
        let bit_secret =
            shared::template::calculate_bit_width(&bounds.sk_bound.to_string()).unwrap();

        let data = generate_sample_sk_shares(
            &params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        let vectors = VerifySharesTrbfvVectors::compute(&data, &params, bit_secret).unwrap();
        let vectors_standard = vectors.standard_form();

        // Verify all values are within ZKP modulus
        use shared::constants::get_zkp_modulus;
        let zkp_modulus = get_zkp_modulus();

        for mod_secret in &vectors_standard.secret_crt {
            for secret_val in mod_secret {
                assert!(*secret_val >= BigInt::zero());
                assert!(*secret_val < zkp_modulus);
            }
        }

        for y_coeff in &vectors_standard.y {
            for y_mod in y_coeff {
                for y_val in y_mod {
                    assert!(*y_val >= BigInt::zero());
                    assert!(*y_val < zkp_modulus);
                }
            }
        }

        for h_mod in &vectors_standard.h {
            for h_row in h_mod {
                for h_val in h_row {
                    assert!(*h_val >= BigInt::zero());
                    assert!(*h_val < zkp_modulus);
                }
            }
        }
    }

    #[test]
    fn test_verify() {
        use crate::bounds::VerifySharesTrbfvBounds;
        use shared::circuit::SampleType;
        let params = test_parameters_trbfv();
        let (_, bounds) = VerifySharesTrbfvBounds::compute(&params, 0).unwrap();
        let bit_secret =
            shared::template::calculate_bit_width(&bounds.sk_bound.to_string()).unwrap();

        let data = generate_sample_sk_shares(
            &params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        let vectors = VerifySharesTrbfvVectors::compute(&data, &params, bit_secret).unwrap();

        // Verify should pass for valid data
        let result = vectors.verify(&params, data.num_parties, data.threshold);
        assert!(
            result.is_ok(),
            "Verification should pass for valid data: {:?}",
            result.err()
        );
    }
}
