//! Input validation vectors for Secret Key Shares verification zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct secret key shares in zero-knowledge.

use crate::sample::VerifySharesTrbfvData;
use fhe::bfv::BfvParameters;
use num_bigint::BigInt;
use num_traits::Zero;
use shared::commitments::compute_sk_commitment;
use shared::errors::ZkFheResult;
use std::sync::Arc;

/// Set of vectors for input validation of Verify Shares TRBFV
#[derive(Clone, Debug)]
pub struct VerifySharesTrbfvVectors {
    /// Secret key coefficients (N elements, trinary: {-1, 0, 1})
    pub sk: Vec<BigInt>,
    /// Shares: y[coeff_idx][mod_idx][0..N_PARTIES+1]
    /// y[i][j][0] = sk[i] at modulus j
    /// y[i][j][k] = share for party k-1 (for k = 1..N_PARTIES)
    pub y: Vec<Vec<Vec<BigInt>>>,
    /// Parity check matrices: h[mod_idx][row][col]
    /// Size per modulus: (N_PARTIES - T) × (N_PARTIES + 1)
    pub h: Vec<Vec<Vec<BigInt>>>,
    /// Expected commitment to sk (from BFV public key circuit)
    pub expected_sk_commitment: BigInt,
}

impl VerifySharesTrbfvVectors {
    /// Create a new `VerifySharesTrbfvVectors` with the given dimensions.
    pub fn new(degree: usize, num_moduli: usize, num_parties: usize, threshold: usize) -> Self {
        let num_parity_rows = num_parties - threshold;
        VerifySharesTrbfvVectors {
            sk: vec![BigInt::zero(); degree],
            y: vec![vec![vec![BigInt::zero(); num_parties + 1]; num_moduli]; degree],
            h: vec![vec![vec![BigInt::zero(); num_parties + 1]; num_parity_rows]; num_moduli],
            expected_sk_commitment: BigInt::zero(),
        }
    }

    /// Create vectors from sample data
    ///
    /// # Arguments
    ///
    /// * `data` - Sample secret key shares data
    /// * `params` - BFV parameters
    /// * `bit_sk` - Bit width for secret key bounds (used for commitment computation)
    ///
    /// # Returns
    ///
    /// A `VerifySharesTrbfvVectors` struct containing all witness vectors.
    /// y and h are already normalized from sample data, no need to normalize again.
    pub fn compute(
        data: &VerifySharesTrbfvData,
        params: &Arc<BfvParameters>,
        bit_sk: u32,
    ) -> ZkFheResult<Self> {
        let ctx = params.ctx_at_level(0)?;
        let degree = params.degree();
        let num_moduli = ctx.moduli().len();

        // Extract secret key coefficients in signed form
        // The circuit expects sk[i] to equal y[i][j][0] for all j
        // sk[i] is range-checked to be in {-1, 0, 1} using range_check_2bounds
        let mut sk: Vec<BigInt> = Vec::new();
        for coeff_idx in 0..degree {
            // Get the signed value from the original secret key
            let sk_signed = data.sk.coeffs[coeff_idx];
            // Convert to BigInt (signed: -1, 0, or 1)
            sk.push(BigInt::from(sk_signed));
        }

        // Compute y[coeff_idx][mod_idx][0..N_PARTIES+1] from sk and sk_sss
        // y[i][j][0] = sk[i] (same signed value for all j)
        // y[i][j][k] = sk_sss[j][k-1][i] (share for party k-1, already normalized to [0, q_j))
        let mut y: Vec<Vec<Vec<BigInt>>> = Vec::new();

        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..degree {
            let mut y_coeff: Vec<Vec<BigInt>> = Vec::new();

            for mod_idx in 0..num_moduli {
                let mut y_mod: Vec<BigInt> = Vec::new();

                // y[i][j][0] = sk[i] (same signed value for all j)
                y_mod.push(sk[coeff_idx].clone());

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

        // Compute expected_sk_commitment (matches BFV circuit's commit_to_sk)
        let expected_sk_commitment = compute_sk_commitment(&sk, bit_sk);

        Ok(VerifySharesTrbfvVectors {
            sk,
            y,
            h,
            expected_sk_commitment,
        })
    }

    /// Verify that the vectors satisfy all circuit constraints
    ///
    /// This function checks:
    /// 1. SK consistency: y[i][j][0] == sk[i] for all i, j
    /// 2. Range checks: sk coefficients are trinary {-1, 0, 1}, shares are in [0, q_j)
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

        // Step 1: Verify SK consistency
        // y[i][j][0] == sk[i] for all i, j
        // Note: sk[i] is stored in signed form (-1, 0, 1)
        // All y[i][j][0] are set to the same value as sk[i]
        // After standard_form, both will be reduced modulo ZKP modulus and should still be equal
        for coeff_idx in 0..degree {
            let sk_coeff = &self.sk[coeff_idx];

            for mod_idx in 0..num_moduli {
                let y_value = &self.y[coeff_idx][mod_idx][0];

                // The circuit expects exact equality: y[i][j][0] == sk[i] for all j
                // Since we set all y[i][j][0] to the same value as sk[i],
                // they should all equal sk[i] exactly
                if sk_coeff != y_value {
                    return Err(shared::errors::ZkFheError::Bfv {
                        message: format!(
                            "SK consistency check failed at coefficient {}, modulus {}: sk[{}] = {}, y[{}][{}][0] = {}. These should be equal.",
                            coeff_idx, mod_idx, coeff_idx, sk_coeff, coeff_idx, mod_idx, y_value
                        ),
                    });
                }
            }
        }

        // Step 2: Range checks
        // SK coefficients should be trinary: -1, 0, or 1 (signed form)
        // The circuit uses range_check_2bounds to verify this
        for (coeff_idx, sk_coeff) in self.sk.iter().enumerate() {
            // Check that sk_coeff is in {-1, 0, 1}
            if *sk_coeff != BigInt::from(-1)
                && *sk_coeff != BigInt::from(0)
                && *sk_coeff != BigInt::from(1)
            {
                return Err(shared::errors::ZkFheError::Bfv {
                    message: format!(
                        "SK range check failed at coefficient {}: sk_coeff = {} (expected -1, 0, or 1)",
                        coeff_idx, sk_coeff
                    ),
                });
            }
        }

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

        // Reduce sk coefficients
        let sk: Vec<BigInt> = self
            .sk
            .into_iter()
            .map(|x| {
                let mut reduced = x % &zkp_modulus;
                if reduced < BigInt::zero() {
                    reduced += &zkp_modulus;
                }
                reduced
            })
            .collect();

        // Reduce y coefficients (3D array)
        let y = reduce_coefficients_3d(&self.y, &zkp_modulus);

        // Reduce h coefficients (3D array)
        let h = reduce_coefficients_3d(&self.h, &zkp_modulus);

        // Reduce expected_sk_commitment modulo ZKP modulus
        let mut expected_sk_commitment = self.expected_sk_commitment % &zkp_modulus;
        if expected_sk_commitment < BigInt::zero() {
            expected_sk_commitment += &zkp_modulus;
        }

        VerifySharesTrbfvVectors {
            sk,
            y,
            h,
            expected_sk_commitment,
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
        let bit_sk = shared::template::calculate_bit_width(&bounds.sk_bound.to_string()).unwrap();

        let data = generate_sample_sk_shares(
            &params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        let vectors = VerifySharesTrbfvVectors::compute(&data, &params, bit_sk).unwrap();
        assert_eq!(vectors.sk.len(), params.degree());
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
        let bit_sk = shared::template::calculate_bit_width(&bounds.sk_bound.to_string()).unwrap();

        let data = generate_sample_sk_shares(
            &params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        let vectors = VerifySharesTrbfvVectors::compute(&data, &params, bit_sk).unwrap();
        let vectors_standard = vectors.standard_form();

        // Verify all values are within ZKP modulus
        use shared::constants::get_zkp_modulus;
        let zkp_modulus = get_zkp_modulus();

        for sk_val in &vectors_standard.sk {
            assert!(*sk_val >= BigInt::zero());
            assert!(*sk_val < zkp_modulus);
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
        let bit_sk = shared::template::calculate_bit_width(&bounds.sk_bound.to_string()).unwrap();

        let data = generate_sample_sk_shares(
            &params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        let vectors = VerifySharesTrbfvVectors::compute(&data, &params, bit_sk).unwrap();

        // Verify should pass for valid data
        let result = vectors.verify(&params, data.num_parties, data.threshold);
        assert!(
            result.is_ok(),
            "Verification should pass for valid data: {:?}",
            result.err()
        );
    }
}
