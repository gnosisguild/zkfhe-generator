//! TOML generation for BFV decryption circuit (no homomorphic addition)
//!
//! This module contains the TOML generation logic specific to the dec_bfv_no_hom_add circuit.

use crate::bounds::{DecBfvNoHomAddBounds, DecBfvNoHomAddCryptographicParameters};
use crate::vectors::DecBfvNoHomAddVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Generator for BFV decryption circuit (no homomorphic addition) TOML files
pub struct DecBfvNoHomAddTomlGenerator {
    crypto_params: DecBfvNoHomAddCryptographicParameters,
    bounds: DecBfvNoHomAddBounds,
    vectors: DecBfvNoHomAddVectors,
}

impl DecBfvNoHomAddTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: DecBfvNoHomAddCryptographicParameters,
        bounds: DecBfvNoHomAddBounds,
        vectors: DecBfvNoHomAddVectors,
    ) -> Self {
        Self {
            crypto_params,
            bounds,
            vectors,
        }
    }
}

/// Complete `Prover.toml` format for BFV decryption circuit (no homomorphic addition)
#[derive(Serialize)]
struct ProverTomlFormat {
    params: serde_json::Value,
    honest_c0: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L']
    honest_c1: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L']
    s: serde_json::Value,
    u_i: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L']
    r_1: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L']
    r_2: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L']
    u_global: Vec<Vec<serde_json::Value>>, // [H][L]
    crt_quotients: Vec<Vec<Vec<serde_json::Value>>>, // [H][L][L']
    decrypted_shares: Vec<Vec<serde_json::Value>>, // [H][L]
    expected_aggregated_shares: Vec<serde_json::Value>, // [L]
}

impl TomlGenerator for DecBfvNoHomAddTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "bfv_qis": self.crypto_params.bfv_moduli.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "bfv_plaintext_modulus": self.crypto_params.bfv_plaintext_modulus.to_string(),
            "bfv_q_inverse_mod_t": self.crypto_params.bfv_q_inverse_mod_t.to_string(),
            "trbfv_qis": self.crypto_params.trbfv_moduli.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "s_bound": self.bounds.s_bound.to_string(),
            "u_i_bounds": self.bounds.u_i_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "u_global_bound": self.bounds.u_global_bound.to_string(),
            "r1_bounds": self.bounds.r1_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r2_bounds": self.bounds.r2_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

        // Convert vectors to TOML format
        // honest_c0[H][L][L'] -> each element is a polynomial with coefficients
        let honest_c0: Vec<Vec<Vec<serde_json::Value>>> = self
            .vectors
            .honest_c0
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        trbfv_basis
                            .iter()
                            .map(|bfv_basis| {
                                serde_json::json!({
                                    "coefficients": to_string_1d_vec(bfv_basis)
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let honest_c1: Vec<Vec<Vec<serde_json::Value>>> = self
            .vectors
            .honest_c1
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        trbfv_basis
                            .iter()
                            .map(|bfv_basis| {
                                serde_json::json!({
                                    "coefficients": to_string_1d_vec(bfv_basis)
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let u_i: Vec<Vec<Vec<serde_json::Value>>> = self
            .vectors
            .u_i
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        trbfv_basis
                            .iter()
                            .map(|bfv_basis| {
                                serde_json::json!({
                                    "coefficients": to_string_1d_vec(bfv_basis)
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let r_1: Vec<Vec<Vec<serde_json::Value>>> = self
            .vectors
            .r_1
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        trbfv_basis
                            .iter()
                            .map(|bfv_basis| {
                                serde_json::json!({
                                    "coefficients": to_string_1d_vec(bfv_basis)
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let r_2: Vec<Vec<Vec<serde_json::Value>>> = self
            .vectors
            .r_2
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        trbfv_basis
                            .iter()
                            .map(|bfv_basis| {
                                serde_json::json!({
                                    "coefficients": to_string_1d_vec(bfv_basis)
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let u_global: Vec<Vec<serde_json::Value>> = self
            .vectors
            .u_global
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        serde_json::json!({
                            "coefficients": to_string_1d_vec(trbfv_basis)
                        })
                    })
                    .collect()
            })
            .collect();

        let crt_quotients: Vec<Vec<Vec<serde_json::Value>>> = self
            .vectors
            .crt_quotients
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        trbfv_basis
                            .iter()
                            .map(|bfv_basis| {
                                serde_json::json!({
                                    "coefficients": to_string_1d_vec(bfv_basis)
                                })
                            })
                            .collect()
                    })
                    .collect()
            })
            .collect();

        let decrypted_shares: Vec<Vec<serde_json::Value>> = self
            .vectors
            .decrypted_shares
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|trbfv_basis| {
                        serde_json::json!({
                            "coefficients": to_string_1d_vec(trbfv_basis)
                        })
                    })
                    .collect()
            })
            .collect();

        let expected_aggregated_shares: Vec<serde_json::Value> = self
            .vectors
            .expected_aggregated_shares
            .iter()
            .map(|trbfv_basis| {
                serde_json::json!({
                    "coefficients": to_string_1d_vec(trbfv_basis)
                })
            })
            .collect();

        let toml_data = ProverTomlFormat {
            params: serde_json::Value::Object(params_json),
            honest_c0,
            honest_c1,
            s: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.s)
            }),
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            decrypted_shares,
            expected_aggregated_shares,
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::DecBfvNoHomAddBounds;
    use crate::vectors::DecBfvNoHomAddVectors;
    use shared::utils::test_parameters;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let bfv_params = test_parameters();
        let trbfv_params = test_parameters();

        let (crypto_params, bounds) =
            DecBfvNoHomAddBounds::compute(&bfv_params, &trbfv_params, 0).unwrap();
        let vectors = DecBfvNoHomAddVectors::new(
            5,                           // H
            trbfv_params.moduli().len(), // L
            bfv_params.moduli().len(),   // L'
            bfv_params.degree(),         // N
        );

        let generator = DecBfvNoHomAddTomlGenerator::new(crypto_params, bounds, vectors);

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
        assert!(content.contains("[s]"));
        assert!(content.contains("u_i"));
        assert!(content.contains("r_1"));
        assert!(content.contains("r_2"));
        assert!(content.contains("u_global"));
        assert!(content.contains("crt_quotients"));
        assert!(content.contains("decrypted_shares"));
        assert!(content.contains("expected_aggregated_shares"));
    }
}
