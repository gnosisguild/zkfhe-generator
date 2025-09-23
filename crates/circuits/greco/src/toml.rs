//! TOML generation for Greco circuit
//!
//! This module contains the TOML generation logic specific to the Greco circuit.

use crate::bounds::{GrecoBounds, GrecoCryptographicParameters};
use crate::vectors::GrecoVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for Greco circuit TOML files
pub struct GrecoTomlGenerator {
    crypto_params: GrecoCryptographicParameters,
    bounds: GrecoBounds,
    vectors: GrecoVectors,
}

impl GrecoTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: GrecoCryptographicParameters,
        bounds: GrecoBounds,
        vectors: GrecoVectors,
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
    ct0is: Vec<serde_json::Value>,
    ct1is: Vec<serde_json::Value>,
    pk0is: Vec<serde_json::Value>,
    pk1is: Vec<serde_json::Value>,
    r1is: Vec<serde_json::Value>,
    r2is: Vec<serde_json::Value>,
    p1is: Vec<serde_json::Value>,
    p2is: Vec<serde_json::Value>,
    u: serde_json::Value,
    e0: serde_json::Value,
    e1: serde_json::Value,
    k1: serde_json::Value,
}

impl TomlGenerator for GrecoTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "q_mod_t": self.crypto_params.q_mod_t.to_string(),
            "qis": self.crypto_params.moduli.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "k0is": self.crypto_params.k0is.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "e_bound": self.bounds.e_bound.to_string(),
            "u_bound": self.bounds.u_bound.to_string(),
            "k1_low_bound": self.bounds.k1_low_bound.to_string(),
            "k1_up_bound": self.bounds.k1_up_bound.to_string(),
            "p1_bounds": self.bounds.p1_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "p2_bounds": self.bounds.p2_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "pk_bounds": self.bounds.pk_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r1_low_bounds": self.bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r1_up_bounds": self.bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r2_bounds": self.bounds.r2_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

        let toml_data = ProverTomlFormat {
            params: serde_json::Value::Object(params_json),
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
            u: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.u)
            }),
            e0: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.e0)
            }),
            e1: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.e1)
            }),
            k1: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.k1)
            }),
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::GrecoBounds;
    use crate::vectors::GrecoVectors;
    use fhe::bfv::BfvParametersBuilder;

    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[0x3FFFFFFF000001])
            .build_arc()
            .unwrap();

        let (crypto_params, bounds) = GrecoBounds::compute(&params, 0).unwrap();
        let vectors = GrecoVectors::new(1, 2048);

        let generator = GrecoTomlGenerator::new(crypto_params, bounds, vectors);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();
        println!("Generated TOML:\n{}", content);
        // Check that the file contains the expected sections
        assert!(content.contains("params.crypto"));
        assert!(content.contains("params.bounds"));
        assert!(content.contains("crypto"));
        assert!(content.contains("bounds"));
        assert!(content.contains("ct0is"));
        assert!(content.contains("ct1is"));
        assert!(content.contains("pk0is"));
        assert!(content.contains("pk1is"));
        assert!(content.contains("r1is"));
        assert!(content.contains("r2is"));
        assert!(content.contains("p1is"));
        assert!(content.contains("p2is"));
        assert!(content.contains("u"));
        assert!(content.contains("e0"));
        assert!(content.contains("e1"));
        assert!(content.contains("k1"));
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("[[ct0is]]"));
        assert!(toml_string.contains("[[ct1is]]"));
        assert!(toml_string.contains("[[pk0is]]"));
        assert!(toml_string.contains("[[pk1is]]"));
        assert!(toml_string.contains("[[r1is]]"));
        assert!(toml_string.contains("[[r2is]]"));
        assert!(toml_string.contains("[[p1is]]"));
        assert!(toml_string.contains("[[p2is]]"));
        assert!(toml_string.contains("[u]"));
        assert!(toml_string.contains("[e0]"));
        assert!(toml_string.contains("[e1]"));
        assert!(toml_string.contains("[k1]"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
