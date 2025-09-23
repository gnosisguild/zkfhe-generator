//! TOML generation for PVW circuit
//!
//! This module contains the TOML generation logic specific to the PVW circuit.

use crate::bounds::{PkPvwBounds, PkPvwCryptographicParameters};
use crate::vectors::PkPvwVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::{matrix_3d_to_format, matrix_to_format};

/// Generator for PVW circuit TOML files
pub struct PkPvwTomlGenerator {
    crypto_params: PkPvwCryptographicParameters,
    bounds: PkPvwBounds,
    vectors: PkPvwVectors,
    circuit_params: CircuitParams,
}

/// Circuit parameters for TOML output
#[derive(Clone, Debug)]
pub struct CircuitParams {
    pub n: usize,         // Ring dimension/polynomial degree
    pub n_parties: usize, // Number of parties
    pub k: usize,         // LWE dimension
}

impl PkPvwTomlGenerator {
    /// Create a new TOML generator with bounds and vectors
    pub fn new(
        crypto_params: PkPvwCryptographicParameters,
        bounds: PkPvwBounds,
        vectors: PkPvwVectors,
        circuit_params: CircuitParams,
    ) -> Self {
        Self {
            crypto_params,
            bounds,
            vectors,
            circuit_params,
        }
    }
}

/// Complete `pk_pvw.toml` format
#[derive(Serialize)]
struct PkPvwTomlFormat {
    a: Vec<Vec<Vec<serde_json::Value>>>,
    e: Vec<Vec<serde_json::Value>>,
    sk: Vec<Vec<serde_json::Value>>,
    b: Vec<Vec<Vec<serde_json::Value>>>,
    r1: Vec<Vec<Vec<serde_json::Value>>>,
    r2: Vec<Vec<Vec<serde_json::Value>>>,
    #[serde(rename = "params")]
    params: ParamsSection,
}

#[derive(Serialize)]
struct ParamsSection {
    bounds: BoundsSection,
    crypto: CryptoSection,
    circuit: CircuitSection,
}

#[derive(Serialize)]
struct BoundsSection {
    e_bound: String,
    r1_low_bounds: Vec<String>,
    r1_up_bounds: Vec<String>,
    r2_bounds: Vec<String>,
    sk_bound: String,
}

#[derive(Serialize)]
struct CryptoSection {
    qis: Vec<String>,
}

#[derive(Serialize)]
struct CircuitSection {
    n: String,
    n_parties: String,
    k: String,
}

impl TomlGenerator for PkPvwTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        let toml_data = PkPvwTomlFormat {
            // a: L matrices of K x K polynomials - convert to 3D array format
            a: matrix_3d_to_format(&self.vectors.a),

            // e: N_PARTIES x K matrix of polynomials - convert to 2D array format
            e: matrix_to_format(&self.vectors.e),

            // sk: N_PARTIES x K matrix of polynomials - convert to 2D array format
            sk: matrix_to_format(&self.vectors.sk),

            // b: L matrices of N_PARTIES x K polynomials - convert to 3D array format
            b: matrix_3d_to_format(&self.vectors.b),

            // r1: L matrices of N_PARTIES x K polynomials - convert to 3D array format
            r1: matrix_3d_to_format(&self.vectors.r1),

            // r2: L matrices of N_PARTIES x K polynomials - convert to 3D array format
            r2: matrix_3d_to_format(&self.vectors.r2),

            params: ParamsSection {
                bounds: BoundsSection {
                    e_bound: self.bounds.e_bound.to_string(),
                    r1_low_bounds: self
                        .bounds
                        .r1_low_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    r1_up_bounds: self
                        .bounds
                        .r1_up_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    r2_bounds: self
                        .bounds
                        .r2_bounds
                        .iter()
                        .map(|b| b.to_string())
                        .collect(),
                    sk_bound: self.bounds.sk_bound.to_string(),
                },
                crypto: CryptoSection {
                    qis: self
                        .crypto_params
                        .qis
                        .iter()
                        .map(|q| q.to_string())
                        .collect(),
                },
                circuit: CircuitSection {
                    n: self.circuit_params.n.to_string(),
                    n_parties: self.circuit_params.n_parties.to_string(),
                    k: self.circuit_params.k.to_string(),
                },
            },
        };

        Ok(toml::to_string(&toml_data)?)
    }
}
