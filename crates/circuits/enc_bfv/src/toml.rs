//! TOML generation for BFV Encryption circuit
//!
//! This module contains the TOML generation logic specific to the enc-bfv circuit.

use crate::vectors::EncBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for BFV Encryption circuit TOML files
pub struct EncBfvTomlGenerator {
    vectors: EncBfvVectors,
}

impl EncBfvTomlGenerator {
    pub fn new(vectors: EncBfvVectors) -> Self {
        Self { vectors }
    }
}

/// Complete `Prover.toml` format for BFV Encryption circuit
#[derive(Serialize)]
struct ProverTomlFormat {
    expected_message_commitment: String,
    pk0is: Vec<serde_json::Value>,
    pk1is: Vec<serde_json::Value>,
    ct0is: Vec<serde_json::Value>,
    ct1is: Vec<serde_json::Value>,
    u: serde_json::Value,
    e0: serde_json::Value,
    e0is: Vec<serde_json::Value>,
    e0_quotients: Vec<serde_json::Value>,
    e1: serde_json::Value,
    message: serde_json::Value,
    r1is: Vec<serde_json::Value>,
    r2is: Vec<serde_json::Value>,
    p1is: Vec<serde_json::Value>,
    p2is: Vec<serde_json::Value>,
}

impl TomlGenerator for EncBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Note: Configs (N, L, QIS, bounds, bit parameters, Configs) are now
        // generated in a separate .nr config file, not in the TOML.

        let toml_data = ProverTomlFormat {
            expected_message_commitment: self.vectors.expected_message_commitment.to_string(),
            pk0is: self
                .vectors
                .pk0is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            pk1is: self
                .vectors
                .pk1is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            ct0is: self
                .vectors
                .ct0is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            ct1is: self
                .vectors
                .ct1is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            u: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.u)
            }),
            e0: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.e0)
            }),
            e0is: self
                .vectors
                .e0is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            e0_quotients: self
                .vectors
                .e0_quotients
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            e1: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.e1)
            }),
            message: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.message)
            }),
            r1is: self
                .vectors
                .r1is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            r2is: self
                .vectors
                .r2is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            p1is: self
                .vectors
                .p1is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            p2is: self
                .vectors
                .p2is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
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
    use crate::vectors::EncBfvVectors;

    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let vectors = EncBfvVectors::new(1, 512);

        let generator = EncBfvTomlGenerator::new(vectors);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();

        // Check that the file contains the expected sections
        assert!(content.contains("expected_message_commitment"));
        assert!(content.contains("pk0is"));
        assert!(content.contains("pk1is"));
        assert!(content.contains("ct0is"));
        assert!(content.contains("ct1is"));
        assert!(content.contains("[u]"));
        assert!(content.contains("[e0]"));
        assert!(content.contains("e0is"));
        assert!(content.contains("e0_quotients"));
        assert!(content.contains("[e1]"));
        assert!(content.contains("[message]"));
        assert!(content.contains("r1is"));
        assert!(content.contains("r2is"));
        assert!(content.contains("p1is"));
        assert!(content.contains("p2is"));
    }
}
