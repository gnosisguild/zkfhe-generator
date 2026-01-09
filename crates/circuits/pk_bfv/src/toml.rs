use crate::vectors::PkBfvVectors;
use serde::Serialize;
use shared::errors::ZkFheResult;
use shared::toml::TomlGenerator;
use shared::utils::to_string_1d_vec;

pub struct PkBfvTomlGenerator {
    vectors: PkBfvVectors,
}

impl PkBfvTomlGenerator {
    pub fn new(vectors: PkBfvVectors) -> Self {
        Self { vectors }
    }
}

/// Complete `Prover.toml` format
#[derive(Serialize)]
struct ProverTomlFormat {
    pk0is: Vec<serde_json::Value>,
    pk1is: Vec<serde_json::Value>,
}

impl TomlGenerator for PkBfvTomlGenerator {
    fn to_toml_string(&self) -> ZkFheResult<String> {
        // Note: Configs (N, L, BIT_PK) are generated in a separate .nr config file, not in the TOML.
        let toml_data = ProverTomlFormat {
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
        };

        Ok(toml::to_string(&toml_data)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vectors::PkBfvVectors;

    use tempfile::TempDir;

    #[test]
    fn test_toml_generation_and_structure() {
        let vectors = PkBfvVectors::new(1, 512);

        let generator = PkBfvTomlGenerator::new(vectors);

        // Create a temporary directory for testing
        let temp_dir = TempDir::new().unwrap();
        let output_path = generator.generate_toml(temp_dir.path()).unwrap();

        // Verify the file was created
        assert!(output_path.exists());
        assert_eq!(output_path.file_name().unwrap(), "Prover.toml");

        // Read and verify the TOML content
        let content = std::fs::read_to_string(&output_path).unwrap();

        // Check that the file contains the expected sections
        assert!(content.contains("pk0is"));
        assert!(content.contains("pk1is"));

        let toml_string = generator.to_toml_string().unwrap();

        // Verify the TOML string contains the expected sections
        assert!(toml_string.contains("[[pk0is]]"));
        assert!(toml_string.contains("[[pk1is]]"));
    }
}
