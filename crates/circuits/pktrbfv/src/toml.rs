use crate::bounds::{PkTrBfvBounds, PkTrBfvCryptographicParameters};
use crate::vectors::PkTrBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

/// Circuit parameters for TOML output
#[derive(Clone, Debug)]
pub struct CircuitParams {
    pub n: usize,
    pub l: usize,
}

pub struct PkTrBfvTomlGenerator {
    crypto_params: PkTrBfvCryptographicParameters,
    bounds: PkTrBfvBounds,
    vectors: PkTrBfvVectors,
    circuit_params: CircuitParams,
}

impl PkTrBfvTomlGenerator {
    pub fn new(
        crypto_params: PkTrBfvCryptographicParameters,
        bounds: PkTrBfvBounds,
        vectors: PkTrBfvVectors,
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

/// Complete `Prover.toml` format
#[derive(Serialize)]
struct ProverTomlFormat {
    #[serde(rename = "params")]
    params: ParamsSection,
    pk0is: Vec<serde_json::Value>,
    pk1is: Vec<serde_json::Value>,
    r1is: Vec<serde_json::Value>,
    r2is: Vec<serde_json::Value>,
    a: Vec<serde_json::Value>,
    sk: serde_json::Value,
    eek: serde_json::Value,
}

#[derive(Serialize)]
struct ParamsSection {
    bounds: BoundsSection,
    crypto: CryptoSection,
    circuit: CircuitSection,
}

#[derive(Serialize)]
struct BoundsSection {
    eek_bound: String,
    sk_bound: String,
    r1_low_bounds: Vec<String>,
    r1_up_bounds: Vec<String>,
    r2_bounds: Vec<String>,
}

#[derive(Serialize)]
struct CryptoSection {
    qis: Vec<String>,
}

#[derive(Serialize)]
struct CircuitSection {
    n: String,
    l: String,
}

impl TomlGenerator for PkTrBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        let toml_data = ProverTomlFormat {
            // a: L vectors of polynomials - convert to simple string format
            a: self
                .vectors
                .a
                .iter()
                .map(|v| {
                    serde_json::json!({
                        "coefficients": to_string_1d_vec(v)
                    })
                })
                .collect(),

            // pk0is: L vectors of polynomials - convert to simple string format
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

            // pk1is: L vectors of polynomials - convert to simple string format
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

            // r1is: L vectors of polynomials - convert to simple string format
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

            // r2is: L vectors of polynomials - convert to simple string format
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

            // sk: single vector of polynomials - convert to simple string format
            sk: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.sk)
            }),

            // eek: single vector of polynomials - convert to simple string format
            eek: serde_json::json!({
                "coefficients": to_string_1d_vec(&self.vectors.eek)
            }),

            params: ParamsSection {
                bounds: BoundsSection {
                    eek_bound: self.bounds.eek_bound.to_string(),
                    sk_bound: self.bounds.sk_bound.to_string(),
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
                },
                crypto: CryptoSection {
                    qis: self
                        .crypto_params
                        .moduli
                        .iter()
                        .map(|q| q.to_string())
                        .collect(),
                },
                circuit: CircuitSection {
                    n: self.circuit_params.n.to_string(),
                    l: self.circuit_params.l.to_string(),
                },
            },
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::PkTrBfvBounds;
    use crate::vectors::PkTrBfvVectors;
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

        let (crypto_params, bounds) = PkTrBfvBounds::compute(&params, 0).unwrap();
        let vectors = PkTrBfvVectors::new(1, 2048);

        let circuit_params = CircuitParams { n: 2048, l: 1 };
        let generator = PkTrBfvTomlGenerator::new(crypto_params, bounds, vectors, circuit_params);

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
        assert!(content.contains("pk0is"));
        assert!(content.contains("pk1is"));
        assert!(content.contains("r1is"));
        assert!(content.contains("r2is"));
        assert!(content.contains("a"));
        assert!(content.contains("sk"));
        assert!(content.contains("eek"));
        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("[[pk0is]]"));
        assert!(toml_string.contains("[[pk1is]]"));
        assert!(toml_string.contains("[[r1is]]"));
        assert!(toml_string.contains("[[r2is]]"));
        assert!(toml_string.contains("[[a]]"));
        assert!(toml_string.contains("[sk]"));
        assert!(toml_string.contains("[eek]"));
        assert!(toml_string.contains("[params.crypto]"));
        assert!(toml_string.contains("[params.bounds]"));
    }
}
