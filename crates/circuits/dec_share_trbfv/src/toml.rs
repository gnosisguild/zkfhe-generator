//! TOML generation for Decryption Share TRBFV circuit
//!
//! This module contains the TOML generation logic specific to the Decryption Share TRBFV circuit.

use crate::bounds::{DecShareTrBfvBounds, DecShareTrBfvCryptographicParameters};
use crate::vectors::DecShareTrBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for Decryption Share TRBFV circuit TOML files
pub struct DecShareTrBfvTomlGenerator {
    crypto_params: DecShareTrBfvCryptographicParameters,
    bounds: DecShareTrBfvBounds,
    vectors: DecShareTrBfvVectors,
}

impl DecShareTrBfvTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: DecShareTrBfvCryptographicParameters,
        bounds: DecShareTrBfvBounds,
        vectors: DecShareTrBfvVectors,
    ) -> Self {
        Self {
            crypto_params,
            bounds,
            vectors,
        }
    }
}

/// Complete `Prover.toml` format
#[derive(Serialize)]
struct ProverTomlFormat {
    params: serde_json::Value,
    c_0: Vec<serde_json::Value>,
    c_1: Vec<serde_json::Value>,
    s: Vec<serde_json::Value>,
    e: Vec<serde_json::Value>,
    r_1: Vec<serde_json::Value>,
    r_2: Vec<serde_json::Value>,
    d: Vec<serde_json::Value>,
}

impl TomlGenerator for DecShareTrBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "qis": self.crypto_params.moduli.iter().map(|m| m.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "decryption_share_bound": self.bounds.decryption_share_bound.to_string(),
            "r1_bounds": self.bounds.r1_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r2_bounds": self.bounds.r2_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

        let toml_data = ProverTomlFormat {
            params: serde_json::Value::Object(params_json),
            c_0: self
                .vectors
                .c_0is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            c_1: self
                .vectors
                .c_1is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            s: self
                .vectors
                .s_is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            e: self
                .vectors
                .e_is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            r_1: self
                .vectors
                .r1is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            r_2: self
                .vectors
                .r2is
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            d: self
                .vectors
                .d_is
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
    use crate::bounds::DecShareTrBfvBounds;
    use crate::vectors::DecShareTrBfvVectors;

    use shared::utils::test_parameters_trbfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let params = test_parameters_trbfv();
        let (crypto_params, bounds) = DecShareTrBfvBounds::compute(&params, 0).unwrap();
        let vectors = DecShareTrBfvVectors::new(1, 512);

        let generator = DecShareTrBfvTomlGenerator::new(crypto_params, bounds, vectors);

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
        assert!(content.contains("crypto"));
        assert!(content.contains("bounds"));
        assert!(content.contains("c_0"));
        assert!(content.contains("c_1"));
        assert!(content.contains("s"));
        assert!(content.contains("e"));
        assert!(content.contains("r_1"));
        assert!(content.contains("r_2"));
        assert!(content.contains("d"));

        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("[[c_0]]"));
        assert!(toml_string.contains("[[c_1]]"));
        assert!(toml_string.contains("[[s]]"));
        assert!(toml_string.contains("[[e]]"));
        assert!(toml_string.contains("[[r_1]]"));
        assert!(toml_string.contains("[[r_2]]"));
        assert!(toml_string.contains("[[d]]"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
