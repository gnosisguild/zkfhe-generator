//! TOML generation for BFV decryption circuit
//!
//! This module contains the TOML generation logic specific to the dec_bfv circuit.

use crate::vectors::DecBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for BFV decryption circuit TOML files
pub struct DecBfvTomlGenerator {
    vectors: DecBfvVectors,
}

impl DecBfvTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(vectors: DecBfvVectors) -> Self {
        Self { vectors }
    }
}

/// Complete `Prover.toml` format for BFV decryption circuit
#[derive(Serialize)]
struct ProverTomlFormat {
    expected_sk_commitment: String,
    honest_c0: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L_PRIME]
    honest_c1: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L_PRIME]
    sum_c0: Vec<Vec<serde_json::Value>>,         // [L][L_PRIME]
    sum_c1: Vec<Vec<serde_json::Value>>,         // [L][L_PRIME]
    s: serde_json::Value,                        // [N] - single polynomial
    u_i: Vec<Vec<serde_json::Value>>,            // [L][L_PRIME]
    r_1: Vec<Vec<serde_json::Value>>,            // [L][L_PRIME]
    r_2: Vec<Vec<serde_json::Value>>,            // [L][L_PRIME]
    u_global: Vec<serde_json::Value>,            // [L]
    crt_quotients: Vec<Vec<serde_json::Value>>,  // [L][L_PRIME]
    message: Vec<serde_json::Value>,             // [L]
}

impl TomlGenerator for DecBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Note: params section removed - cryptographic parameters and bounds are now in separate config file

        let toml_data = ProverTomlFormat {
            expected_sk_commitment: self.vectors.expected_sk_commitment.to_string(),
            honest_c0: self
                .vectors
                .honest_c0
                .iter()
                .map(|party_c0| {
                    party_c0
                        .iter()
                        .map(|trbfv_c0| {
                            trbfv_c0
                                .iter()
                                .map(|bfv_c0| {
                                    serde_json::json!({
                                        "coefficients": to_string_1d_vec(bfv_c0)
                                    })
                                })
                                .collect()
                        })
                        .collect()
                })
                .collect(),
            honest_c1: self
                .vectors
                .honest_c1
                .iter()
                .map(|party_c1| {
                    party_c1
                        .iter()
                        .map(|trbfv_c1| {
                            trbfv_c1
                                .iter()
                                .map(|bfv_c1| {
                                    serde_json::json!({
                                        "coefficients": to_string_1d_vec(bfv_c1)
                                    })
                                })
                                .collect()
                        })
                        .collect()
                })
                .collect(),
            sum_c0: self
                .vectors
                .sum_c0
                .iter()
                .map(|trbfv_c0| {
                    trbfv_c0
                        .iter()
                        .map(|bfv_c0| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(bfv_c0)
                            })
                        })
                        .collect()
                })
                .collect(),
            sum_c1: self
                .vectors
                .sum_c1
                .iter()
                .map(|trbfv_c1| {
                    trbfv_c1
                        .iter()
                        .map(|bfv_c1| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(bfv_c1)
                            })
                        })
                        .collect()
                })
                .collect(),
            s: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.s)
            }),
            u_i: self
                .vectors
                .u_i
                .iter()
                .map(|trbfv_u_i| {
                    trbfv_u_i
                        .iter()
                        .map(|bfv_u_i| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(bfv_u_i)
                            })
                        })
                        .collect()
                })
                .collect(),
            r_1: self
                .vectors
                .r_1
                .iter()
                .map(|trbfv_r1| {
                    trbfv_r1
                        .iter()
                        .map(|bfv_r1| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(bfv_r1)
                            })
                        })
                        .collect()
                })
                .collect(),
            r_2: self
                .vectors
                .r_2
                .iter()
                .map(|trbfv_r2| {
                    trbfv_r2
                        .iter()
                        .map(|bfv_r2| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(bfv_r2)
                            })
                        })
                        .collect()
                })
                .collect(),
            u_global: self
                .vectors
                .u_global
                .iter()
                .map(|trbfv_u_global| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(trbfv_u_global)
                    })
                })
                .collect(),
            crt_quotients: self
                .vectors
                .crt_quotients
                .iter()
                .map(|trbfv_crt| {
                    trbfv_crt
                        .iter()
                        .map(|bfv_crt| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(bfv_crt)
                            })
                        })
                        .collect()
                })
                .collect(),
            message: self
                .vectors
                .message
                .iter()
                .map(|trbfv_msg| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(trbfv_msg)
                    })
                })
                .collect(),
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::DecBfvVectors;
    use shared::utils::test_parameters_bfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        use shared::utils::test_parameters_trbfv;
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();

        let vectors = DecBfvVectors::new(
            3,
            trbfv_params.moduli().len(),
            bfv_params.moduli().len(),
            bfv_params.degree(),
        );

        let generator = DecBfvTomlGenerator::new(vectors);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();

        // Check that the file contains the expected sections
        assert!(content.contains("expected_sk_commitment"));
        assert!(content.contains("honest_c0"));
        assert!(content.contains("honest_c1"));
        assert!(content.contains("sum_c0"));
        assert!(content.contains("sum_c1"));
        assert!(content.contains("[s]"));
        assert!(content.contains("[[u_global]]"));
        assert!(content.contains("[[message]]"));
    }

    #[test]
    fn test_toml_string_format() {
        use shared::utils::test_parameters_trbfv;
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();
        let vectors = DecBfvVectors::new(
            3,
            trbfv_params.moduli().len(),
            bfv_params.moduli().len(),
            bfv_params.degree(),
        );

        let generator = DecBfvTomlGenerator::new(vectors);
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("honest_c0"));
        assert!(toml_string.contains("honest_c1"));
        assert!(toml_string.contains("sum_c0"));
        assert!(toml_string.contains("sum_c1"));
        assert!(toml_string.contains("s"));
        assert!(toml_string.contains("u_global"));
        assert!(toml_string.contains("message"));
        assert!(toml_string.contains("expected_sk_commitment"));
    }
}
