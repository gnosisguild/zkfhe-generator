//! BFV Decryption circuit implementation
//!
//! This module provides the circuit interface for the dec_bfv circuit,
//! which proves correct BFV decryption of encrypted Shamir shares.

use crate::bounds::DecBfvBounds;
use crate::sample::generate_sample_decryption;
use crate::toml::DecBfvTomlGenerator;
use crate::vectors::DecBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// BFV Decryption circuit implementation
///
/// This circuit proves correct decryption of BFV ciphertexts containing
/// encrypted Shamir shares. It verifies:
/// 1. The decryption formula: u_i = c_0i + c_1i * s + r_2i * (X^N + 1) + r_1i * qi
/// 2. CRT reconstruction of u_i into u_global
/// 3. Correct decoding to recover the plaintext message
pub struct DecBfvCircuit {
    /// The sample type to use for share generation
    ///
    /// This determines whether to generate secret key shares (SecretKey) or
    /// smudging error shares (SmudgingNoise) when creating sample decryption data.
    pub sample_type: SampleType,
}

impl DecBfvCircuit {
    /// Create a new DecBfvCircuit instance with the specified sample type
    ///
    /// # Arguments
    ///
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    pub fn new(sample_type: SampleType) -> Self {
        DecBfvCircuit { sample_type }
    }
}

impl Default for DecBfvCircuit {
    fn default() -> Self {
        Self::new(SampleType::SecretKey)
    }
}

impl Circuit for DecBfvCircuit {
    /// Returns the name of the BFV decryption circuit
    fn name(&self) -> &'static str {
        "dec-bfv"
    }

    /// Returns a description of the BFV decryption circuit
    fn description(&self) -> &'static str {
        "Zero-knowledge proof circuit for BFV decryption of encrypted Shamir shares"
    }

    /// Returns the parameter type this circuit uses
    fn parameter_type(&self) -> ParameterType {
        ParameterType::Bfv // Uses BFV parameters (not trBFV)
    }

    /// Generate TOML file with sample data and parameters
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // dec_bfv uses BFV parameters (for share encryption/decryption)
        let selected_params = bfv_params;

        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = DecBfvBounds::compute(selected_params, 0)?;

        // Generate sample decryption data
        let decryption_data = generate_sample_decryption(
            bfv_params,
            trbfv_params,
            self.sample_type,
            ciphernodes_config,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        // Compute witness vectors from the decryption data
        let vectors = DecBfvVectors::compute(
            &decryption_data.honest_ciphertexts,
            &decryption_data.sum_ciphertext,
            &decryption_data.message,
            &decryption_data.secret_key,
            selected_params,
        )?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = DecBfvTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_bfv;
    use tempfile::TempDir;

    #[test]
    fn test_circuit_name_and_description() {
        let circuit = DecBfvCircuit::new(SampleType::SecretKey);
        assert_eq!(circuit.name(), "dec-bfv");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Bfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit = DecBfvCircuit::new(SampleType::SecretKey);
        let params = test_parameters_bfv();
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
        assert!(content.contains("honest_c0"));
        assert!(content.contains("sum_c0"));
        assert!(content.contains("message"));
    }

    #[test]
    #[should_panic(expected = "Failed to generate smudging error")]
    fn test_toml_generation_smudging_noise() {
        let circuit = DecBfvCircuit::new(SampleType::SmudgingNoise);
        let params = test_parameters_bfv();
        let temp_dir = TempDir::new().unwrap();

        circuit
            .generate_toml(&params, &params, temp_dir.path(), None)
            .unwrap();
    }
}
