//! Secret Key Shares verification circuit implementation
//!
//! This module provides the circuit interface for the sk_shares circuit,
//! which verifies that Shamir secret key shares satisfy the Reed-Solomon parity check.

use crate::bounds::SkSharesBounds;
use crate::sample::generate_sample_sk_shares;
use crate::toml::SkSharesTomlGenerator;
use crate::vectors::SkSharesVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// Secret Key Shares verification circuit implementation
///
/// This circuit verifies that Shamir secret key shares satisfy the Reed-Solomon parity check.
/// It verifies:
/// 1. sk consistency: y[i][j][0] == sk[i] for all i, j
/// 2. Range checks: sk coefficients are trinary {-1, 0, 1}, shares are in [0, q_j)
/// 3. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
pub struct SkSharesCircuit {
    /// The parameter type this circuit is configured with
    pub parameter_type: ParameterType,
    /// The sample type to use for share generation
    ///
    /// This determines whether to generate sk_sss (SecretKey) or
    /// es_sss (SmudgingNoise) shares when creating sample data.
    pub sample_type: SampleType,
}

impl SkSharesCircuit {
    /// Create a new SkSharesCircuit instance with the specified parameter type and sample type
    ///
    /// # Arguments
    ///
    /// * `parameter_type` - The parameter type (Trbfv or Bfv)
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    pub fn new(parameter_type: ParameterType, sample_type: SampleType) -> Self {
        SkSharesCircuit {
            parameter_type,
            sample_type,
        }
    }
}

impl Circuit for SkSharesCircuit {
    /// Returns the name of the Secret Key Shares verification circuit
    fn name(&self) -> &'static str {
        "sk-shares"
    }

    /// Returns a description of the Secret Key Shares verification circuit
    fn description(&self) -> &'static str {
        "Zero-knowledge proof circuit for verifying that Shamir secret key shares satisfy the Reed-Solomon parity check"
    }

    /// Returns the parameter type this circuit uses
    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    /// Generate TOML file with sample data and parameters
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        _bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // sk_shares uses TRBFV parameters
        let selected_params = trbfv_params;

        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = SkSharesBounds::compute(selected_params, 0)?;

        // Generate sample secret key shares data
        let shares_data =
            generate_sample_sk_shares(selected_params, self.sample_type, ciphernodes_config)
                .map_err(|e| shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                })?;

        // Compute witness vectors from the shares data
        let vectors = SkSharesVectors::compute(&shares_data, selected_params)?;

        // Verify that vectors satisfy circuit constraints
        vectors.verify(
            selected_params,
            shares_data.num_parties,
            shares_data.threshold,
        )?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = SkSharesTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_trbfv;
    use tempfile::TempDir;

    #[test]
    fn test_circuit_name_and_description() {
        let circuit = SkSharesCircuit::new(ParameterType::Trbfv, SampleType::SecretKey);
        assert_eq!(circuit.name(), "sk-shares");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Trbfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit = SkSharesCircuit::new(ParameterType::Trbfv, SampleType::SecretKey);
        let params = test_parameters_trbfv();
        let temp_dir = TempDir::new().unwrap();

        let result = circuit.generate_toml(&params, &params, temp_dir.path(), None);
        assert!(
            result.is_ok(),
            "TOML generation should succeed: {:?}",
            result.err()
        );

        // Verify the file was created
        let toml_path = temp_dir.path().join("Prover.toml");
        assert!(toml_path.exists(), "Prover.toml should be created");

        // Read and verify basic structure
        let content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("params"));
        assert!(content.contains("sk"));
        assert!(content.contains("y"));
        assert!(content.contains("h"));
    }
}
