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
    /// Create a new TOML generator with vectors
    pub fn new(vectors: DecBfvVectors) -> Self {
        Self { vectors }
    }
}

/// Complete `Prover.toml` format for BFV decryption circuit
#[derive(Serialize)]
struct ProverTomlFormat {
    expected_commitments: Vec<Vec<String>>,        // [H][L]
    decrypted_shares: Vec<Vec<serde_json::Value>>, // [H][L]
}

impl TomlGenerator for DecBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        let toml_data = ProverTomlFormat {
            expected_commitments: self
                .vectors
                .expected_commitments
                .iter()
                .map(|party_commitments| party_commitments.iter().map(|c| c.to_string()).collect())
                .collect(),
            decrypted_shares: self
                .vectors
                .decrypted_shares
                .iter()
                .map(|party_shares| {
                    party_shares
                        .iter()
                        .map(|share| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(share)
                            })
                        })
                        .collect()
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
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_toml_generation_and_structure() {
        let trbfv_params = test_parameters_trbfv();
        let vectors = DecBfvVectors::new(3, trbfv_params.moduli().len(), 512);

        let generator = DecBfvTomlGenerator::new(vectors);

        // Create a temporary directory for testing
        let temp_dir = tempfile::TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();

        // Check that the file contains the expected sections
        assert!(content.contains("expected_commitments"));
        assert!(content.contains("decrypted_shares"));
    }

    #[test]
    fn test_toml_string_format() {
        let trbfv_params = test_parameters_trbfv();
        let vectors = DecBfvVectors::new(3, trbfv_params.moduli().len(), 512);

        let generator = DecBfvTomlGenerator::new(vectors);
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("expected_commitments"));
        assert!(toml_string.contains("decrypted_shares"));
    }
}
