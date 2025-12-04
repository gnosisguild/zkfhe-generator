//! TOML generation for BFV decryption circuit
//!
//! This module contains the TOML generation logic specific to the dec_bfv circuit.

use crate::bounds::{DecBfvBounds, DecBfvCryptographicParameters};
use crate::vectors::DecBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for BFV decryption circuit TOML files
pub struct DecBfvTomlGenerator {
    crypto_params: DecBfvCryptographicParameters,
    bounds: DecBfvBounds,
    vectors: DecBfvVectors,
}

impl DecBfvTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: DecBfvCryptographicParameters,
        bounds: DecBfvBounds,
        vectors: DecBfvVectors,
    ) -> Self {
        Self {
            crypto_params,
            bounds,
            vectors,
        }
    }
}

/// Complete `Prover.toml` format for BFV decryption circuit
#[derive(Serialize)]
struct ProverTomlFormat {
    params: serde_json::Value,
    honest_c0: Vec<Vec<serde_json::Value>>, // [H][L]
    honest_c1: Vec<Vec<serde_json::Value>>, // [H][L]
    sum_c0: Vec<serde_json::Value>,
    sum_c1: Vec<serde_json::Value>,
    s: Vec<serde_json::Value>,
    u_i: Vec<serde_json::Value>,
    r_1: Vec<serde_json::Value>,
    r_2: Vec<serde_json::Value>,
    u_global: serde_json::Value,
    crt_quotients: Vec<serde_json::Value>,
    message: serde_json::Value,
}

impl TomlGenerator for DecBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "qis": self.crypto_params.moduli.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "plaintext_modulus": self.crypto_params.plaintext_modulus.to_string(),
            "q_inverse_mod_t": self.crypto_params.q_inverse_mod_t.to_string(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "s_bound": self.bounds.s_bound.to_string(),
            "u_i_bounds": self.bounds.u_i_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "u_global_bound": self.bounds.u_global_bound.to_string(),
            "r1_bounds": self.bounds.r1_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r2_bounds": self.bounds.r2_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "delta": self.bounds.delta.to_string(),
            "delta_half": self.bounds.delta_half.to_string(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

        let toml_data = ProverTomlFormat {
            params: serde_json::Value::Object(params_json),
            honest_c0: self
                .vectors
                .honest_c0
                .iter()
                .map(|party_c0| {
                    party_c0
                        .iter()
                        .map(|v| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(v)
                            })
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
                        .map(|v| {
                            serde_json::json!({
                                "coefficients": to_string_1d_vec(v)
                            })
                        })
                        .collect()
                })
                .collect(),
            sum_c0: self
                .vectors
                .sum_c0
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            sum_c1: self
                .vectors
                .sum_c1
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            s: self
                .vectors
                .s
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            u_i: self
                .vectors
                .u_i
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            r_1: self
                .vectors
                .r_1
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            r_2: self
                .vectors
                .r_2
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            u_global: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.u_global)
            }),
            crt_quotients: self
                .vectors
                .crt_quotients
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),
            message: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.message)
            }),
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::DecBfvBounds;
    use crate::vectors::DecBfvVectors;
    use shared::utils::test_parameters_bfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let params = test_parameters_bfv();

        let (crypto_params, bounds) = DecBfvBounds::compute(&params, 0).unwrap();
        let vectors = DecBfvVectors::new(3, params.moduli().len(), params.degree());

        let generator = DecBfvTomlGenerator::new(crypto_params, bounds, vectors);

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
        assert!(content.contains("honest_c0"));
        assert!(content.contains("honest_c1"));
        assert!(content.contains("sum_c0"));
        assert!(content.contains("sum_c1"));
        assert!(content.contains("[[s]]"));
        assert!(content.contains("[[u_i]]"));
        assert!(content.contains("[[r_1]]"));
        assert!(content.contains("[[r_2]]"));
        assert!(content.contains("[u_global]"));
        assert!(content.contains("[[crt_quotients]]"));
        assert!(content.contains("[message]"));
    }

    #[test]
    fn test_toml_string_format() {
        let params = test_parameters_bfv();
        let (crypto_params, bounds) = DecBfvBounds::compute(&params, 0).unwrap();
        let vectors = DecBfvVectors::new(3, params.moduli().len(), params.degree());

        let generator = DecBfvTomlGenerator::new(crypto_params, bounds, vectors);
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("honest_c0"));
        assert!(toml_string.contains("honest_c1"));
        assert!(toml_string.contains("[[sum_c0]]"));
        assert!(toml_string.contains("[[sum_c1]]"));
        assert!(toml_string.contains("[[s]]"));
        assert!(toml_string.contains("[[u_i]]"));
        assert!(toml_string.contains("[u_global]"));
        assert!(toml_string.contains("[message]"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
