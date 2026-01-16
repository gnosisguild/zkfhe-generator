use crate::vectors::PkAggTrBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::{to_string_2d_vec, to_string_3d_vec};

pub struct PkAggTrBfvTomlGenerator {
    vectors: PkAggTrBfvVectors,
}

impl PkAggTrBfvTomlGenerator {
    pub fn new(vectors: PkAggTrBfvVectors) -> Self {
        Self { vectors }
    }
}

/// Complete `Prover.toml` format
#[derive(Serialize)]
struct ProverTomlFormat {
    expected_pk_trbfv_commitments: Vec<String>,
    pk0: Vec<Vec<serde_json::Value>>,
    pk1: Vec<Vec<serde_json::Value>>,
    pk0_agg: Vec<serde_json::Value>,
    pk1_agg: Vec<serde_json::Value>,
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

        // Convert expected_pk_trbfv_commitments to strings
        let expected_pk_trbfv_commitments: Vec<String> = self
            .vectors
            .expected_pk_trbfv_commitments
            .iter()
            .map(|c| c.to_string())
            .collect();

        let toml_data = ProverTomlFormat {
            expected_pk_trbfv_commitments,
            pk0: pk0_json,
            pk1: pk1_json,
            pk0_agg: pk0_agg_json,
            pk1_agg: pk1_agg_json,
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
        use crate::bounds::PkAggTrBfvCryptographicParameters;
        let params: std::sync::Arc<fhe::bfv::BfvParameters> = test_parameters_trbfv();

        let data = generate_sample_pk_aggregation(&params, None).unwrap();
        let crypto_params = PkAggTrBfvCryptographicParameters::compute(&params, 0).unwrap();
        let bit_pk =
            shared::template::calculate_bit_width(&crypto_params.pk_bound.to_string()).unwrap();
        let vectors = PkAggTrBfvVectors::compute(&data, &params, bit_pk).unwrap();
        let vectors_standard = vectors.standard_form();

        let generator = PkAggTrBfvTomlGenerator::new(vectors_standard);

        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        let content = std::fs::read_to_string(&output_path).unwrap();
        assert!(content.contains("expected_pk_trbfv_commitments"));
        assert!(content.contains("pk0"));
        assert!(content.contains("pk1"));
        assert!(content.contains("pk0_agg"));
        assert!(content.contains("pk1_agg"));
    }
}
