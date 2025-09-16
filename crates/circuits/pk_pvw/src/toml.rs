//! TOML generation for PVW circuit
//!
//! This module contains the TOML generation logic specific to the PVW circuit.

use crate::bounds::{PkPvwBounds, PkPvwCryptographicParameters};
use crate::vectors::PkPvwVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::{to_string_3d_vec, to_string_4d_vec};

/// Generator for PVW circuit TOML files
pub struct PkPvwTomlGenerator {
    crypto_params: PkPvwCryptographicParameters,
    bounds: PkPvwBounds,
    vectors: PkPvwVectors,
}

impl PkPvwTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: PkPvwCryptographicParameters,
        bounds: PkPvwBounds,
        vectors: PkPvwVectors,
    ) -> Self {
        Self {
            crypto_params,
            bounds,
            vectors,
        }
    }
}

/// Complete `pk_pvw.toml` format
#[derive(Serialize)]
struct PkPvwTomlFormat {
    params: serde_json::Value,
    a: Vec<serde_json::Value>,
    e: Vec<serde_json::Value>,
    sk: Vec<serde_json::Value>,
    b: Vec<serde_json::Value>,
    r1: Vec<serde_json::Value>,
    r2: Vec<serde_json::Value>,
}

impl TomlGenerator for PkPvwTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Create params JSON by combining crypto params and bounds
        let mut params_json = serde_json::Map::new();

        // Add crypto params
        let crypto_json = serde_json::json!({
            "qis": self.crypto_params.qis.iter().map(|q| q.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("crypto".to_string(), crypto_json);

        // Add bounds
        let bounds_json = serde_json::json!({
            "e_bound": self.bounds.e_bound.to_string(),
            "sk_bound": self.bounds.sk_bound.to_string(),
            "r1_low_bounds": self.bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r1_up_bounds": self.bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
            "r2_bounds": self.bounds.r2_bounds.iter().map(|b| b.to_string()).collect::<Vec<_>>(),
        });
        params_json.insert("bounds".to_string(), bounds_json);

        let toml_data = PkPvwTomlFormat {
            params: serde_json::Value::Object(params_json),
            a: self
                .vectors
                .a
                .iter()
                .map(|matrix| {
                    serde_json::json!({
                        "coefficients": to_string_4d_vec(&[matrix.clone()])
                    })
                })
                .collect(),
            e: self
                .vectors
                .e
                .iter()
                .map(|party_vector| {
                    serde_json::json!({
                        "coefficients": to_string_3d_vec(&[party_vector.clone()])
                    })
                })
                .collect(),
            sk: self
                .vectors
                .sk
                .iter()
                .map(|party_vector| {
                    serde_json::json!({
                        "coefficients": to_string_3d_vec(&[party_vector.clone()])
                    })
                })
                .collect(),
            b: self
                .vectors
                .b
                .iter()
                .map(|matrix| {
                    serde_json::json!({
                        "coefficients": to_string_4d_vec(&[matrix.clone()])
                    })
                })
                .collect(),
            r1: self
                .vectors
                .r1
                .iter()
                .map(|matrix| {
                    serde_json::json!({
                        "coefficients": to_string_4d_vec(&[matrix.clone()])
                    })
                })
                .collect(),
            r2: self
                .vectors
                .r2
                .iter()
                .map(|matrix| {
                    serde_json::json!({
                        "coefficients": to_string_4d_vec(&[matrix.clone()])
                    })
                })
                .collect(),
        };

        Ok(toml::to_string(&toml_data)?)
    }
}
