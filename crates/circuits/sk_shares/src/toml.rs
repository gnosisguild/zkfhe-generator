use serde::Serialize;
use serde_json::{Value, json};
use shared::{TomlGenerator, ZkFheResult};
use toml::to_string;

use crate::bounds::{SkSharesBounds, SkSharesCryptographicParameters};
use crate::vectors::SkSharesVectors;

/// Generator for sk_shares circuit TOML files
pub struct SkSharesTomlGenerator {
    crypto_params: SkSharesCryptographicParameters,
    bounds: SkSharesBounds,
    vectors: SkSharesVectors,
    circuit_params: CircuitParams,
}

#[derive(Clone, Debug)]
pub struct CircuitParams {
    pub n: usize,         // Ring dimension/polynomial degree
    pub n_parties: usize, // Number of parties
    pub t: usize,
}

impl SkSharesTomlGenerator {
    pub fn new(
        crypto_params: SkSharesCryptographicParameters,
        bounds: SkSharesBounds,
        vectors: SkSharesVectors,
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

#[derive(Serialize)]
struct SkSharesTomlFormat {
    sk: Value,                      // {"coefficients": [..]}
    f: Vec<Vec<Value>>,             // [N][L] of {"coefficients": [..]} (highest-first)
    y: Vec<Vec<Value>>,             // [N][L] of {"coefficients": [..]}
    r: Vec<Vec<Value>>,             // [N][L] of {"coefficients": [..]}
    d: Vec<Vec<String>>,            // [N][L]
    f_randomness: Vec<Vec<String>>, // [N][L]
    x_coords: Vec<String>,          // [P]
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
    sk_bound: String,
    r_lower_bound: String,
    r_upper_bound: String,
    randomness_bound: String,
}

#[derive(Serialize)]
struct CryptoSection {
    qis: Vec<String>,
}

#[derive(Serialize)]
struct CircuitSection {
    n: String,
    n_parties: String,
    t: String,
}

impl TomlGenerator for SkSharesTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        let sk: Value = json!({
            "coefficients": self.vectors.sk
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<String>>()
        });

        let f: Vec<Vec<Value>> = self
            .vectors
            .f
            .iter()
            .map(|row| {
                row.iter()
                    .map(|poly_cf| {
                        let mut tmp = poly_cf.clone();
                        tmp.reverse(); // highest-first
                        json!({
                            "coefficients": tmp.into_iter()
                                .map(|c| c.to_string())
                                .collect::<Vec<String>>()
                        })
                    })
                    .collect::<Vec<Value>>()
            })
            .collect::<Vec<Vec<Value>>>();

        let y: Vec<Vec<Value>> = self
            .vectors
            .y
            .iter()
            .map(|row| {
                row.iter()
                    .map(|col| {
                        json!({
                            "coefficients": col.iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<String>>()
                        })
                    })
                    .collect::<Vec<Value>>()
            })
            .collect::<Vec<Vec<Value>>>();

        let r: Vec<Vec<Value>> = self
            .vectors
            .r
            .iter()
            .map(|row| {
                row.iter()
                    .map(|col| {
                        json!({
                            "coefficients": col.iter()
                                .map(|v| v.to_string())
                                .collect::<Vec<String>>()
                        })
                    })
                    .collect::<Vec<Value>>()
            })
            .collect::<Vec<Vec<Value>>>();

        let d: Vec<Vec<String>> = self
            .vectors
            .d
            .iter()
            .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<String>>())
            .collect::<Vec<Vec<String>>>();

        let f_randomness: Vec<Vec<String>> = self
            .vectors
            .f_randomness
            .iter()
            .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<String>>())
            .collect::<Vec<Vec<String>>>();

        let x_coords: Vec<String> = self
            .vectors
            .x_coords
            .iter()
            .map(|x| x.to_string())
            .collect::<Vec<String>>();

        let params = ParamsSection {
            bounds: BoundsSection {
                sk_bound: self.bounds.sk_bound.to_string(),
                r_lower_bound: self.bounds.r_lower_bound.to_string(),
                r_upper_bound: self.bounds.r_upper_bound.to_string(),
                randomness_bound: self.bounds.randomness_bound.to_string(),
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
                t: self.circuit_params.t.to_string(),
            },
        };

        let toml_data = SkSharesTomlFormat {
            sk,
            f,
            y,
            r,
            d,
            f_randomness,
            x_coords,
            params,
        };

        Ok(to_string(&toml_data)?)
    }
}
