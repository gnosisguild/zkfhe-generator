//! TOML generation for Decryption Share Aggregation TRBFV circuit
//!
//! This module contains the TOML generation logic specific to the Decryption Share Aggregation TRBFV circuit.

use crate::bounds::{DecShareAggTrBfvBounds, DecShareAggTrBfvCryptographicParameters};
use crate::vectors::DecShareAggTrBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for Decryption Share Aggregation TRBFV circuit TOML files
pub struct DecShareAggTrBfvTomlGenerator {
    crypto_params: DecShareAggTrBfvCryptographicParameters,
    bounds: DecShareAggTrBfvBounds,
    vectors: DecShareAggTrBfvVectors,
}

impl DecShareAggTrBfvTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: DecShareAggTrBfvCryptographicParameters,
        bounds: DecShareAggTrBfvBounds,
        vectors: DecShareAggTrBfvVectors,
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
    decryption_shares: Vec<Vec<serde_json::Value>>, // [party][modulus]
    crt_quotients: Vec<serde_json::Value>,
    message: serde_json::Value,
    u_global: serde_json::Value,
    party_ids: Vec<String>,
}

impl TomlGenerator for DecShareAggTrBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "qis": self.crypto_params.moduli.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "plaintext_modulus": self.crypto_params.plaintext_modulus.to_string(),
            "q_inverse_mod_t": self.crypto_params.q_inverse_mod_t.to_string(),
            "q_mod_t": self.crypto_params.q_mod_t.to_string(),
            "t_inv_mod_q": self.crypto_params.t_inv_mod_q.to_string(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "delta": self.bounds.delta.to_string(),
            "delta_half": self.bounds.delta_half.to_string(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

        // Format decryption_shares as [party][modulus] structure
        let decryption_shares: Vec<Vec<serde_json::Value>> = self
            .vectors
            .decryption_shares
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|modulus| {
                        serde_json::json!({
                            "coefficients": to_string_1d_vec(modulus)
                        })
                    })
                    .collect()
            })
            .collect();

        let toml_data = ProverTomlFormat {
            params: serde_json::Value::Object(params_json),
            decryption_shares,
            message: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.message)
            }),
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
            party_ids: self
                .vectors
                .party_ids
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>(),
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::DecShareAggTrBfvBounds;
    use crate::vectors::DecShareAggTrBfvVectors;
    use shared::utils::test_parameters_trbfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let params = test_parameters_trbfv();
        let (crypto_params, bounds) = DecShareAggTrBfvBounds::compute(&params, 0).unwrap();

        // Create empty vectors for testing
        let vectors = DecShareAggTrBfvVectors::new(1, 2048, 2);

        let generator = DecShareAggTrBfvTomlGenerator::new(crypto_params, bounds, vectors);

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
        assert!(content.contains("decryption_shares"));
        assert!(content.contains("party_ids"));
        assert!(content.contains("message"));
        assert!(content.contains("u_global"));
        assert!(content.contains("crt_quotients"));

        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("decryption_shares"));
        assert!(toml_string.contains("party_ids"));
        assert!(toml_string.contains("[message]"));
        assert!(toml_string.contains("[u_global]"));
        assert!(toml_string.contains("[[crt_quotients]]"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
