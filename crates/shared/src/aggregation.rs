//! Wrapper circuit template generation for zkFHE circuits
//!
//! This module provides functionality for generating wrapper circuit templates
//! that aggregate multiple proofs and their commitments. The wrapper is
//! parameterized by N_PROOFS (number of proofs to aggregate) and N_PUBLIC_INPUTS
//! (number of public inputs/outputs per proof).

use crate::errors::ZkFheResult;
use std::path::Path;

/// Parameters for generating wrapper circuit templates
#[derive(Debug, Clone)]
pub struct WrapperTemplateParams {
    /// Number of proofs to aggregate (N_PROOFS)
    pub n_proofs: u32,
    /// Number of public inputs/outputs per proof (N_PUBLIC_INPUTS)
    pub public_inputs: u32,
}

/// Generator for wrapper circuit templates
pub struct WrapperTemplateGenerator;

impl WrapperTemplateGenerator {
    /// Generate the wrapper template content
    ///
    /// Generates a Noir template that aggregates multiple proofs and their public inputs.
    /// The template follows the pattern:
    /// - Takes verification_key, proofs array, public_inputs array, and key_hash
    /// - Verifies each proof
    /// - Aggregates all public inputs
    /// - Returns the aggregated commitment
    pub fn generate_template(&self, params: &WrapperTemplateParams) -> ZkFheResult<String> {
        let template = format!(
            r#"use bb_proof_verification::{{UltraHonkProof, UltraHonkVerificationKey, verify_honk_proof_non_zk}};
use lib::math::commitments::compute_aggregation_commitment;

// Number of proofs.
pub global N_PROOFS: u32 = {};
/// Number of public inputs/outputs per proof.
pub global N_PUBLIC_INPUTS: u32 = {};

fn main(
    verification_key: UltraHonkVerificationKey,
    proofs: [UltraHonkProof; N_PROOFS],
    public_inputs: pub [[Field; N_PUBLIC_INPUTS]; N_PROOFS],
    key_hash: Field,
) -> pub Field {{
    for i in 0..N_PROOFS {{
        verify_honk_proof_non_zk(verification_key, proofs[i], public_inputs[i], key_hash);
    }}

    let mut aggregated_public_inputs = Vec::new();

    for i in 0..N_PROOFS {{
        for j in 0..N_PUBLIC_INPUTS {{
            aggregated_public_inputs.push(public_inputs[i][j]);
        }}
    }}

    compute_aggregation_commitment(aggregated_public_inputs)
}}
"#,
            params.n_proofs, params.public_inputs
        );

        Ok(template)
    }

    /// Generate and write the wrapper template to the output directory
    ///
    /// # Arguments
    ///
    /// * `params` - The wrapper template parameters
    /// * `output_dir` - The directory where the wrapper.nr file should be written
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the template was generated successfully, or an error otherwise
    pub fn generate_wrapper_file(
        &self,
        params: &WrapperTemplateParams,
        output_dir: &Path,
    ) -> ZkFheResult<()> {
        let content = self.generate_template(params)?;
        let wrapper_nr_path = output_dir.join("wrapper.nr");
        std::fs::write(&wrapper_nr_path, content)?;
        Ok(())
    }
}

/// Get the number of proofs (N_PROOFS) for a given circuit
///
/// Returns 2 for verify_shares_trbfv, enc_bfv, and dec_bfv circuits.
/// Returns 1 for all other circuits.
pub fn get_n_proofs(circuit_name: &str) -> u32 {
    match circuit_name.to_lowercase().as_str() {
        "verify-shares-trbfv" | "enc-bfv" | "dec-bfv" => 2,
        _ => 1,
    }
}

/// Parameters for calculating dynamic public input counts
#[derive(Debug, Clone, Default)]
pub struct CommitmentParams {
    /// Polynomial degree (N)
    pub n: Option<usize>,
    /// Number of moduli (L)
    pub l: Option<usize>,
    /// Number of moduli for TRBFV (L_TRBFV)
    pub l_trbfv: Option<usize>,
    /// Number of parties (N_PARTIES)
    pub num_parties: Option<usize>,
    /// Number of honest parties (H)
    pub num_honest_parties: Option<usize>,
    /// Threshold (T)
    pub threshold: Option<usize>,
    /// Max number of non-zero coefficients in message polynomial (MAX_MSG_NON_ZERO_COEFFS)
    pub max_msg_non_zero_coeffs: Option<usize>,
}

/// Get the number of public inputs/outputs (N_PUBLIC_INPUTS) for a given circuit
///
/// Returns the number of `pub` input/output parameters in the circuit's main function.
/// For some circuits (like verify-shares-trbfv), this depends on dynamic parameters like L and N_PARTIES.
///
/// # Arguments
///
/// * `circuit_name` - The name of the circuit
/// * `params` - Optional parameters for dynamic calculation (L, N_PARTIES, etc.)
///
/// # Returns
///
/// The number of `pub` parameters (public inputs/outputs) for the circuit, or an error if required parameters are missing
pub fn get_n_public_inputs(
    circuit_name: &str,
    params: Option<&CommitmentParams>,
) -> ZkFheResult<u32> {
    match circuit_name.to_lowercase().as_str() {
        "pk-bfv" => {
            // Output: -> pub Field = 1 public output
            Ok(1)
        }
        "pk-trbfv" => {
            // Input: a: pub [Polynomial<N>; L] = L * N public inputs
            // Output: -> pub (Field, Field, Field) = 3 public outputs
            // Total: L * N + 3
            if let Some(p) = params {
                if let (Some(l), Some(n)) = (p.l, p.n) {
                    return Ok(((l * n) + 3) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "pk-trbfv requires L and N parameters. Got: L={:?}, N={:?}",
                    params.and_then(|p| p.l),
                    params.and_then(|p| p.n)
                ),
            })
        }
        "verify-shares-trbfv" => {
            // Input: expected_secret_commitment: pub Field = 1 public input
            // Output: -> pub [[Field; L]; N_PARTIES] = L * N_PARTIES public outputs
            // Total: 1 + (L * N_PARTIES)
            if let Some(p) = params {
                if let (Some(l), Some(n_parties)) = (p.l, p.num_parties) {
                    return Ok(1 + (l * n_parties) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "verify-shares-trbfv requires L and N_PARTIES parameters. Got: L={:?}, N_PARTIES={:?}",
                    params.and_then(|p| p.l),
                    params.and_then(|p| p.num_parties)
                ),
            })
        }
        "enc-bfv" => {
            // Inputs:
            // - expected_pk_commitment: pub Field = 1 public input
            // - expected_message_commitment: pub Field = 1 public input
            // - ct0is: pub [Polynomial<N>; L] = L * N public inputs
            // - ct1is: pub [Polynomial<N>; L] = L * N public inputs
            // Output: none (no pub return)
            // Total: 2 + 2 * L * N
            if let Some(p) = params {
                if let (Some(l), Some(n)) = (p.l, p.n) {
                    return Ok((2 + 2 * l * n) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "enc-bfv requires L and N parameters. Got: L={:?}, N={:?}",
                    params.and_then(|p| p.l),
                    params.and_then(|p| p.n)
                ),
            })
        }
        "dec-bfv" => {
            // Input: expected_commitments: pub [[Field; L_TRBFV]; H] = H * L_TRBFV public inputs
            // Output: -> pub Field = 1 public output
            // Total: H * L_TRBFV + 1
            if let Some(p) = params {
                if let (Some(h), Some(l_trbfv)) = (p.num_honest_parties, p.l_trbfv) {
                    return Ok((h * l_trbfv + 1) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "dec-bfv requires H and L_TRBFV parameters. Got: H={:?}, L_TRBFV={:?}",
                    params.and_then(|p| p.num_honest_parties),
                    params.and_then(|p| p.l_trbfv)
                ),
            })
        }
        "pk-agg-trbfv" => {
            // Input: expected_pk_trbfv_commitments: pub [Field; H] = H public inputs
            // Output: -> pub Field = 1 public output
            // Total: H + 1
            if let Some(p) = params {
                if let Some(h) = p.num_honest_parties {
                    return Ok((h + 1) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "pk-agg-trbfv requires H parameter. Got: H={:?}",
                    params.and_then(|p| p.num_honest_parties)
                ),
            })
        }
        "greco" => {
            // Input: pk_commitment: pub Field = 1 public input
            // Output: none
            Ok(1)
        }
        "dec-share-trbfv" => {
            // Inputs:
            // - expected_s_commitment: pub Field = 1 public input
            // - expected_e_commitment: pub Field = 1 public input
            // - c_0: pub [Polynomial<N>; L] = L * N public inputs
            // - c_1: pub [Polynomial<N>; L] = L * N public inputs
            // - d: pub [Polynomial<N>; L] = L * N public inputs
            // Output: none
            // Total: 2 + 3 * L * N
            if let Some(p) = params {
                if let (Some(l), Some(n)) = (p.l, p.n) {
                    return Ok((2 + 3 * l * n) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "dec-share-trbfv requires L and N parameters. Got: L={:?}, N={:?}",
                    params.and_then(|p| p.l),
                    params.and_then(|p| p.n)
                ),
            })
        }
        "dec-shares-agg-trbfv" => {
            // Inputs:
            // - decryption_shares: pub [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1]
            //   = (T + 1) * L * MAX_MSG_NON_ZERO_COEFFS public inputs
            // - party_ids: pub [Field; T + 1] = T + 1 public inputs
            // - message: pub Polynomial<MAX_MSG_NON_ZERO_COEFFS> = MAX_MSG_NON_ZERO_COEFFS public inputs
            // Total: (T + 1) * L * MAX_MSG_NON_ZERO_COEFFS + (T + 1) + MAX_MSG_NON_ZERO_COEFFS
            if let Some(p) = params {
                if let (Some(l), Some(t), Some(max_coeffs)) =
                    (p.l, p.threshold, p.max_msg_non_zero_coeffs)
                {
                    return Ok((((t + 1) * l * max_coeffs) + (t + 1) + max_coeffs) as u32);
                }
            }
            Err(crate::errors::ZkFheError::Bfv {
                message: format!(
                    "dec-shares-agg-trbfv requires T, L, and MAX_MSG_NON_ZERO_COEFFS parameters. Got: T={:?}, L={:?}, MAX_MSG_NON_ZERO_COEFFS={:?}",
                    params.and_then(|p| p.threshold),
                    params.and_then(|p| p.l),
                    params.and_then(|p| p.max_msg_non_zero_coeffs)
                ),
            })
        }
        _ => Err(crate::errors::ZkFheError::Bfv {
            message: format!("Unknown circuit: {}", circuit_name),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_n_proofs() {
        assert_eq!(get_n_proofs("verify-shares-trbfv"), 2);
        assert_eq!(get_n_proofs("enc-bfv"), 2);
        assert_eq!(get_n_proofs("dec-bfv"), 2);
        assert_eq!(get_n_proofs("pk-trbfv"), 1);
        assert_eq!(get_n_proofs("greco"), 1);
    }

    #[test]
    fn test_get_n_public_inputs() {
        assert_eq!(
            get_n_public_inputs("dec-share-trbfv", None)
                .unwrap_err()
                .to_string()
                .contains("requires"),
            true
        );
        assert_eq!(get_n_public_inputs("greco", None).unwrap(), 1);
        assert_eq!(
            get_n_public_inputs("pk-trbfv", None)
                .unwrap_err()
                .to_string()
                .contains("requires"),
            true
        );
        assert_eq!(
            get_n_public_inputs("enc-bfv", None)
                .unwrap_err()
                .to_string()
                .contains("requires"),
            true
        );

        // Test verify-shares-trbfv with dynamic params
        let params = CommitmentParams {
            n: Some(512),
            l: Some(4),
            l_trbfv: Some(4),
            num_parties: Some(5),
            num_honest_parties: Some(5),
            threshold: Some(2),
            max_msg_non_zero_coeffs: Some(80),
        };
        // 1 input + (4 * 5) outputs = 21
        assert_eq!(
            get_n_public_inputs("verify-shares-trbfv", Some(&params)).unwrap(),
            21
        );

        // Test pk-trbfv with dynamic params
        // L * N + 3 = 4 * 512 + 3 = 2048 + 3 = 2051
        assert_eq!(
            get_n_public_inputs("pk-trbfv", Some(&params)).unwrap(),
            2051
        );

        // Test pk-agg-trbfv with dynamic params
        // H + 1 = 5 + 1 = 6
        assert_eq!(
            get_n_public_inputs("pk-agg-trbfv", Some(&params)).unwrap(),
            6
        );

        // Test dec-shares-agg-trbfv with dynamic params
        // (T + 1) * L * MAX_MSG_NON_ZERO_COEFFS + (T + 1) + MAX_MSG_NON_ZERO_COEFFS
        // = 3 * 4 * 80 + 3 + 80 = 960 + 3 + 80 = 1043
        assert_eq!(
            get_n_public_inputs("dec-shares-agg-trbfv", Some(&params)).unwrap(),
            1043
        );

        // Test dec-bfv with dynamic params
        // H * L_TRBFV + 1 = 5 * 4 + 1 = 21
        assert_eq!(get_n_public_inputs("dec-bfv", Some(&params)).unwrap(), 21);

        // Test enc-bfv with dynamic params
        // 2 + 2 * L * N = 2 + 2 * 4 * 512 = 2 + 4096 = 4098
        assert_eq!(get_n_public_inputs("enc-bfv", Some(&params)).unwrap(), 4098);

        // Test dec-share-trbfv with dynamic params
        // 2 + 3 * L * N = 2 + 3 * 4 * 512 = 2 + 6144 = 6146
        assert_eq!(
            get_n_public_inputs("dec-share-trbfv", Some(&params)).unwrap(),
            6146
        );

        // Test without params (should return error for dynamic circuits)
        assert!(get_n_public_inputs("verify-shares-trbfv", None).is_err());
        assert!(get_n_public_inputs("pk-trbfv", None).is_err());
        assert!(get_n_public_inputs("pk-agg-trbfv", None).is_err());
        assert!(get_n_public_inputs("dec-shares-agg-trbfv", None).is_err());
        assert!(get_n_public_inputs("dec-bfv", None).is_err());
        assert!(get_n_public_inputs("enc-bfv", None).is_err());
        assert!(get_n_public_inputs("dec-share-trbfv", None).is_err());
    }
}
