//! TOML serialization for the `sk_shares` circuit.
//!
//! This module converts precomputed vectors (secret key, Shamir polynomials, shares,
//! quotients, etc.) and their associated parameters into a single TOML payload
//! consumable by the circuit/prover.
//!
//! ## Conventions
//! - All integers are serialized as **decimal strings** to avoid size/precision limits.
//! - Polynomial coefficients are encoded in **constant-first** order:
//!   `a0, a1, ..., a_T` (with `a0` the constant term).
//! - Shapes (by index families):
//!   - `N`  : ring dimension (number of secret coefficients).
//!   - `L`  : number of CRT moduli.
//!   - `P`  : number of parties / evaluation points.
//!   - `T+1`: number of coefficients per Shamir polynomial.

use crate::bounds::{SkSharesBounds, SkSharesCryptographicParameters};
use crate::vectors::SkSharesVectors;
use serde::Serialize;
use shared::{TomlGenerator, ZkFheResult};
use toml::to_string;

/// Builder that assembles all sections required by the `sk_shares` circuit
/// and renders them into a TOML document.
pub struct SkSharesTomlGenerator {
    /// Cryptographic parameters (e.g., the CRT moduli `q_i`).
    crypto_params: SkSharesCryptographicParameters,
    /// Scalar bounds used for range checks in the circuit.
    bounds: SkSharesBounds,
    /// Witness vectors (secret key, Shamir polynomials, shares, etc.).
    vectors: SkSharesVectors,
    /// Circuit sizing parameters (`N`, `P`, `T`).
    circuit_params: CircuitParams,
}

/// Circuit sizing parameters attached to the TOML output.
#[derive(Clone, Debug)]
pub struct CircuitParams {
    /// Ring dimension / number of secret coefficients (`N`).
    pub n: usize,
    /// Number of parties / share points (`P`).
    pub n_parties: usize,
    /// Shamir polynomial degree (`T`), so each polynomial has `T+1` coefficients.
    pub t: usize,
}

/// Serializable polynomial in constant-first order.
#[derive(Serialize)]
struct PolynomialToml {
    /// `[a0, a1, ..., a_T]` with `a0` the constant term.
    coefficients: Vec<String>,
}

/// Complete TOML payload for the `sk_shares` circuit.
///
/// Sections:
/// - `sk` : the secret key as a polynomial of length `N`.
/// - `f`  : per-coefficient, per-modulus Shamir polynomials, each of length `T+1`.
/// - `y`  : residue shares `y[i][j][k]`.
/// - `r`  : quotient shares `r[i][j][k]`.
/// - `d`  : lift gaps `d[i][j]`.
/// - `f_randomness` : commitment randomness per `(i, j)`.
/// - `x_coords` : public evaluation points for parties.
/// - `params` : bounds, crypto, and circuit metadata.
#[derive(Serialize)]
struct SkSharesTomlFormat {
    /// Secret key polynomial (`N` coefficients).
    sk: PolynomialToml,
    /// Shamir polynomials: shape `[N][L]`, each `PolynomialToml` has `T+1` coefficients.
    f: Vec<Vec<PolynomialToml>>,
    /// Residue shares: shape `[N][L][P]`.
    y: Vec<Vec<Vec<String>>>,
    /// Quotient shares: shape `[N][L][P]`.
    r: Vec<Vec<Vec<String>>>,
    /// Lift gaps: shape `[N][L]`.
    d: Vec<Vec<String>>,
    /// Commitment randomness: shape `[N][L]`.
    f_randomness: Vec<Vec<String>>,
    /// Party evaluation points: shape `[P]`.
    x_coords: Vec<String>,
    /// Bounds, CRT moduli, and circuit dimensions.
    params: ParamsSection,
}

/// Parameter sections grouped for TOML serialization.
#[derive(Serialize)]
struct ParamsSection {
    /// Scalar bounds used by the circuit.
    bounds: BoundsSection,
    /// CRT moduli and other cryptographic constants.
    crypto: CryptoSection,
    /// Dimension parameters (`N`, `P`, `T`).
    circuit: CircuitSection,
}

/// Bounds encoded as strings.
#[derive(Serialize)]
struct BoundsSection {
    /// Absolute bound for each secret coefficient.
    sk_bound: String,
    /// Lower bound for quotient values `r`.
    r_lower_bound: String,
    /// Upper bound for quotient values `r`.
    r_upper_bound: String,
    /// Absolute bound for commitment randomness.
    randomness_bound: String,
}

/// CRT moduli encoded as strings.
#[derive(Serialize)]
struct CryptoSection {
    /// `q_i` values in decimal string form.
    qis: Vec<String>,
}

/// Circuit dimension parameters encoded as strings.
#[derive(Serialize)]
struct CircuitSection {
    /// `N`
    n: String,
    /// `P`
    n_parties: String,
    /// `T`
    t: String,
}

impl SkSharesTomlGenerator {
    /// Constructs a new generator from parameters, bounds, and witness vectors.
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
    /// Produces a TOML string containing all sections required by the circuit.
    ///
    /// All numeric entries are rendered as decimal strings. Arrays preserve the
    /// original shapes described in this module’s conventions.
    fn to_toml_string(&self) -> ZkFheResult<String> {
        let sk = PolynomialToml {
            coefficients: self.vectors.sk.iter().map(|c| c.to_string()).collect(),
        };

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

        let d: Vec<Vec<String>> = self
            .vectors
            .d
            .iter()
            .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<String>>())
            .collect();

        let f_randomness: Vec<Vec<String>> = self
            .vectors
            .f_randomness
            .iter()
            .map(|row| row.iter().map(|v| v.to_string()).collect::<Vec<String>>())
            .collect();

        let x_coords: Vec<String> = self
            .vectors
            .x_coords
            .iter()
            .map(|x| x.to_string())
            .collect();

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
