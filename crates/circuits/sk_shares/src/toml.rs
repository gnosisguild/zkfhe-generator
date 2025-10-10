use crate::bounds::{SkSharesBounds, SkSharesCryptographicParameters};
use crate::vectors::SkSharesVectors;
use serde::Serialize;
use shared::{TomlGenerator, ZkFheResult};
use toml::to_string;

pub struct SkSharesTomlGenerator {
    crypto_params: SkSharesCryptographicParameters,
    bounds: SkSharesBounds,
    vectors: SkSharesVectors,
    circuit_params: CircuitParams,
}

#[derive(Clone, Debug)]
pub struct CircuitParams {
    pub n: usize,
    pub n_parties: usize,
    pub t: usize,
}

#[derive(Serialize)]
struct PolynomialToml {
    coefficients: Vec<String>, // constant-first: a0, a1, ..., a_T
}

#[derive(Serialize)]
struct SkSharesTomlFormat {
    // --- Struct-encoded polynomials ---
    sk: PolynomialToml,          // Polynomial<N>
    f: Vec<Vec<PolynomialToml>>, // [N][L] of Polynomial<T+1>
    // --- Raw arrays (Fields as strings are fine) ---
    y: Vec<Vec<Vec<String>>>,       // [N][L][P]
    r: Vec<Vec<Vec<String>>>,       // [N][L][P]
    d: Vec<Vec<String>>,            // [N][L]
    f_randomness: Vec<Vec<String>>, // [N][L]
    x_coords: Vec<String>,          // [P]
    // --- Params ---
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

impl TomlGenerator for SkSharesTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // sk
        let sk = PolynomialToml {
            coefficients: self.vectors.sk.iter().map(|c| c.to_string()).collect(),
        };

        // f: [N][L] of Polynomial (STRUCT), constant-first (NO reverse)
        let f: Vec<Vec<PolynomialToml>> = self
            .vectors
            .f
            .iter()
            .map(|row| {
                row.iter()
                    .map(|poly_cf| PolynomialToml {
                        coefficients: poly_cf.iter().map(|c| c.to_string()).collect(),
                    })
                    .collect::<Vec<PolynomialToml>>()
            })
            .collect::<Vec<Vec<PolynomialToml>>>();

        // y: [N][L][P] raw arrays
        let y: Vec<Vec<Vec<String>>> = self
            .vectors
            .y
            .iter()
            .map(|row| {
                row.iter()
                    .map(|col| col.iter().map(|v| v.to_string()).collect::<Vec<String>>())
                    .collect::<Vec<Vec<String>>>()
            })
            .collect();

        // r: [N][L][P] raw arrays
        let r: Vec<Vec<Vec<String>>> = self
            .vectors
            .r
            .iter()
            .map(|row| {
                row.iter()
                    .map(|col| col.iter().map(|v| v.to_string()).collect::<Vec<String>>())
                    .collect::<Vec<Vec<String>>>()
            })
            .collect();

        // d: [N][L]
        let d: Vec<Vec<String>> = self
            .vectors
            .d
            .iter()
            .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<String>>())
            .collect();

        // f_randomness: [N][L]
        let f_randomness: Vec<Vec<String>> = self
            .vectors
            .f_randomness
            .iter()
            .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<String>>())
            .collect();

        // x_coords: [P]
        let x_coords: Vec<String> = self
            .vectors
            .x_coords
            .iter()
            .map(|x| x.to_string())
            .collect();

        // params
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
