//! TOML generation for Secret Key Shares verification circuit
//!
//! This module contains the TOML generation logic specific to the sk_shares circuit.

use crate::bounds::{SkSharesBounds, SkSharesCryptographicParameters};
use crate::vectors::SkSharesVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::{to_string_1d_vec, to_string_3d_vec};

/// Generator for Secret Key Shares circuit TOML files
pub struct SkSharesTomlGenerator {
    crypto_params: SkSharesCryptographicParameters,
    bounds: SkSharesBounds,
    vectors: SkSharesVectors,
}

impl SkSharesTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: SkSharesCryptographicParameters,
        bounds: SkSharesBounds,
        vectors: SkSharesVectors,
    ) -> Self {
        Self {
            crypto_params,
            bounds,
            vectors,
        }
    }
}

/// Complete `Prover.toml` format for Secret Key Shares circuit
#[derive(Serialize)]
struct ProverTomlFormat {
    params: serde_json::Value,
    sk: serde_json::Value,
    y: Vec<Vec<Vec<serde_json::Value>>>, // [N][L][N_PARTIES+1]
    h: Vec<Vec<Vec<serde_json::Value>>>, // [L][N_PARTIES-T][N_PARTIES+1]
}

impl TomlGenerator for SkSharesTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "qis": self.crypto_params.moduli.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "plaintext_modulus": self.crypto_params.plaintext_modulus.to_string(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "sk_bound": self.bounds.sk_bound.to_string(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

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
            params: serde_json::Value::Object(params_json),
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
    use crate::bounds::SkSharesBounds;
    use crate::sample::generate_sample_sk_shares;
    use crate::vectors::SkSharesVectors;
    use shared::utils::test_parameters_trbfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let params = test_parameters_trbfv();

        let (crypto_params, bounds) = SkSharesBounds::compute(&params, 0).unwrap();
        let data = generate_sample_sk_shares(&params, None).unwrap();
        let vectors = SkSharesVectors::compute(&data, &params).unwrap();
        let vectors_standard = vectors.standard_form();

        let generator = SkSharesTomlGenerator::new(crypto_params, bounds, vectors_standard);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();

        // Check that the file contains the expected sections
        assert!(content.contains("params.crypto"));
        assert!(content.contains("params.bounds"));
        assert!(content.contains("[sk]"));
        assert!(content.contains("y"));
        assert!(content.contains("h"));
    }

    #[test]
    fn test_toml_string_format() {
        let params = test_parameters_trbfv();

        let (crypto_params, bounds) = SkSharesBounds::compute(&params, 0).unwrap();
        let data = generate_sample_sk_shares(&params, None).unwrap();
        let vectors = SkSharesVectors::compute(&data, &params).unwrap();
        let vectors_standard = vectors.standard_form();

        let generator = SkSharesTomlGenerator::new(crypto_params, bounds, vectors_standard);
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("[sk]"));
        assert!(toml_string.contains("y"));
        assert!(toml_string.contains("h"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
