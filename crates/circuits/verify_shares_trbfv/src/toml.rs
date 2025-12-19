//! TOML generation for Verify Shares TRBFV circuit
//!
//! This module contains the TOML generation logic specific to the verify-shares-trbfv circuit.

use crate::vectors::VerifySharesTrbfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::{to_string_1d_vec, to_string_3d_vec};

/// Generator for Verify Shares TRBFV circuit TOML files
pub struct VerifySharesTrbfvTomlGenerator {
    vectors: VerifySharesTrbfvVectors,
}

impl VerifySharesTrbfvTomlGenerator {
    /// Create a new TOML generator with vectors
    /// Note: Constants (N, L, QIS, bounds, etc.) are now in a separate .nr file
    pub fn new(vectors: VerifySharesTrbfvVectors) -> Self {
        Self { vectors }
    }
}

/// Complete `Prover.toml` format for Verify Shares TRBFV circuit
#[derive(Serialize)]
struct ProverTomlFormat {
    expected_sk_commitment: String,
    sk: serde_json::Value,
    y: Vec<Vec<Vec<serde_json::Value>>>, // [N][L][N_PARTIES+1]
    h: Vec<Vec<Vec<serde_json::Value>>>, // [L][N_PARTIES-T][N_PARTIES+1]
}

impl TomlGenerator for VerifySharesTrbfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Note: Configs (N, L, QIS, bounds, bit parameters, Configs) are now
        // generated in a separate .nr config file, not in the TOML.

        // Convert y to JSON format: [N][L][N_PARTIES+1]
        // Each element is a Field value
        let y_strings = to_string_3d_vec(&self.vectors.y);
        let y_json: Vec<Vec<Vec<serde_json::Value>>> = y_strings
            .iter()
            .map(|coeff| {
                coeff
                    .iter()
                    .map(|modulus| {
                        modulus
                            .iter()
                            .map(|val| serde_json::json!(val))
                            .collect::<Vec<serde_json::Value>>()
                    })
                    .collect::<Vec<Vec<serde_json::Value>>>()
            })
            .collect::<Vec<Vec<Vec<serde_json::Value>>>>();

        // Convert h to JSON format: [L][N_PARTIES-T][N_PARTIES+1]
        // Each element is a Field value
        let h_strings: Vec<Vec<Vec<String>>> = self
            .vectors
            .h
            .iter()
            .map(|modulus| modulus.iter().map(|row| to_string_1d_vec(row)).collect())
            .collect();
        let h_json: Vec<Vec<Vec<serde_json::Value>>> = h_strings
            .iter()
            .map(|modulus| {
                modulus
                    .iter()
                    .map(|row| {
                        row.iter()
                            .map(|val| serde_json::json!(val))
                            .collect::<Vec<serde_json::Value>>()
                    })
                    .collect::<Vec<Vec<serde_json::Value>>>()
            })
            .collect::<Vec<Vec<Vec<serde_json::Value>>>>();

        let toml_data = ProverTomlFormat {
            expected_sk_commitment: self.vectors.expected_sk_commitment.to_string(),
            sk: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.sk)
            }),
            y: y_json,
            h: h_json,
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::VerifySharesTrbfvBounds;
    use crate::sample::generate_sample_sk_shares;
    use crate::vectors::VerifySharesTrbfvVectors;
    use shared::utils::test_parameters_trbfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
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

        let generator = VerifySharesTrbfvTomlGenerator::new(vectors_standard);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();

        // Check that the file contains the expected sections
        // Note: params are now in a separate .nr constant file, not in TOML
        assert!(content.contains("expected_sk_commitment"));
        assert!(content.contains("[sk]"));
        assert!(content.contains("y"));
        assert!(content.contains("h"));
    }

    #[test]
    fn test_toml_string_format() {
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

        let generator = VerifySharesTrbfvTomlGenerator::new(vectors_standard);
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        // Note: params are now in a separate .nr constant file, not in TOML
        assert!(toml_string.contains("expected_sk_commitment"));
        assert!(toml_string.contains("[sk]"));
        assert!(toml_string.contains("y"));
        assert!(toml_string.contains("h"));
    }
}
