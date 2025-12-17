use crate::bounds::PkAggTrBfvCryptographicParameters;
use crate::vectors::PkAggTrBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::{to_string_2d_vec, to_string_3d_vec};

pub struct PkAggTrBfvTomlGenerator {
    crypto_params: PkAggTrBfvCryptographicParameters,
    vectors: PkAggTrBfvVectors,
}

impl PkAggTrBfvTomlGenerator {
    pub fn new(
        crypto_params: PkAggTrBfvCryptographicParameters,
        vectors: PkAggTrBfvVectors,
    ) -> Self {
        Self {
            crypto_params,
            vectors,
        }
    }
}

/// Complete `Prover.toml` format
#[derive(Serialize)]
struct ProverTomlFormat {
    #[serde(rename = "params")]
    params: ParamsSection,
    pk0: Vec<Vec<serde_json::Value>>,
    pk1: Vec<Vec<serde_json::Value>>,
    pk0_agg: Vec<serde_json::Value>,
    pk1_agg: Vec<serde_json::Value>,
}

#[derive(Serialize)]
struct ParamsSection {
    crypto: CryptoSection,
}

#[derive(Serialize)]
struct CryptoSection {
    qis: Vec<String>,
}

impl TomlGenerator for PkAggTrBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Convert pk0: [H][L][N] -> array of arrays
        // Each party has L bases, each basis is a polynomial
        let pk0_strings = to_string_3d_vec(&self.vectors.pk0);
        let pk0_json: Vec<Vec<serde_json::Value>> = pk0_strings
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|basis| {
                        serde_json::json!({
                            "coefficients": basis
                        })
                    })
                    .collect()
            })
            .collect();

        // Convert pk1: [H][L][N] -> array of arrays
        let pk1_strings = to_string_3d_vec(&self.vectors.pk1);
        let pk1_json: Vec<Vec<serde_json::Value>> = pk1_strings
            .iter()
            .map(|party| {
                party
                    .iter()
                    .map(|basis| {
                        serde_json::json!({
                            "coefficients": basis
                        })
                    })
                    .collect()
            })
            .collect();

        // Convert pk0_agg: [L][N] -> array
        let pk0_agg_strings = to_string_2d_vec(&self.vectors.pk0_agg);
        let pk0_agg_json: Vec<serde_json::Value> = pk0_agg_strings
            .iter()
            .map(|basis| {
                serde_json::json!({
                    "coefficients": basis
                })
            })
            .collect();

        // Convert pk1_agg: [L][N] -> array
        let pk1_agg_strings = to_string_2d_vec(&self.vectors.pk1_agg);
        let pk1_agg_json: Vec<serde_json::Value> = pk1_agg_strings
            .iter()
            .map(|basis| {
                serde_json::json!({
                    "coefficients": basis
                })
            })
            .collect();

        let toml_data = ProverTomlFormat {
            pk0: pk0_json,
            pk1: pk1_json,
            pk0_agg: pk0_agg_json,
            pk1_agg: pk1_agg_json,
            params: ParamsSection {
                crypto: CryptoSection {
                    qis: self
                        .crypto_params
                        .moduli
                        .iter()
                        .map(|q| q.to_string())
                        .collect(),
                },
            },
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_pk_aggregation;
    use crate::vectors::PkAggTrBfvVectors;
    use shared::utils::test_parameters_trbfv;
    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let params = test_parameters_trbfv();

        let data = generate_sample_pk_aggregation(&params, None).unwrap();
        let vectors = PkAggTrBfvVectors::compute(&data, &params).unwrap();
        let vectors_standard = vectors.standard_form();

        let generator = PkAggTrBfvTomlGenerator::new(
            PkAggTrBfvCryptographicParameters {
                moduli: params.moduli().to_vec(),
            },
            vectors_standard,
        );

        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("params.crypto"));
        assert!(content.contains("pk0"));
        assert!(content.contains("pk1"));
        assert!(content.contains("pk0_agg"));
        assert!(content.contains("pk1_agg"));
    }
}
