//! BFV Decryption circuit implementation
//!
//! This module provides the circuit interface for the dec_bfv circuit,
//! which proves correct BFV decryption of encrypted Shamir shares.

use crate::configs::DecBfvConfigsGenerator;
use crate::sample::generate_sample_decryption;
use crate::template::DecBfvTemplateParams;
use crate::toml::DecBfvTomlGenerator;
use crate::vectors::DecBfvVectors;
use fhe::bfv::{BfvParameters, Ciphertext};
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
use shared::template::calculate_bit_width;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// BFV Decryption circuit implementation
///
/// This circuit verifies correct BFV decryption operations.
/// The message can be either sk shares (Circuit 4a) or e_sm shares (Circuit 4b).
/// It verifies:
/// 1. Each decrypted share from H honest parties matches its commitment from Circuit 3
/// 2. Computes sum of all shares
/// 3. Returns commitment to aggregated shares
pub struct DecBfvCircuit {
    /// The sample type to use for share generation
    ///
    /// This determines whether to generate secret key shares (SecretKey) or
    /// smudging error shares (SmudgingNoise) when creating sample decryption data.
    pub sample_type: SampleType,
    /// The security parameter (λ) this circuit is configured with
    ///
    /// This value is explicitly stored and can be used for fhe.rs function calls
    /// that require the security parameter. Parameters are considered secure
    /// if lambda >= 80, and insecure if lambda < 80.
    pub security_parameter: usize,
}

impl DecBfvCircuit {
    /// Create a new DecBfvCircuit instance with the specified sample type and security parameter
    ///
    /// # Arguments
    ///
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    /// * `lambda` - The security parameter (λ)
    pub fn new(sample_type: SampleType, lambda: usize) -> Self {
        DecBfvCircuit {
            sample_type,
            security_parameter: lambda,
        }
    }
}

impl Default for DecBfvCircuit {
    fn default() -> Self {
        Self::new(SampleType::SecretKey, shared::DEFAULT_SECURE_LAMBDA) // Default to secure lambda
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

    fn security_parameter(&self) -> usize {
        self.security_parameter
    }

    /// Generate TOML file with sample data and parameters
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate sample decryption data
        let decryption_data = generate_sample_decryption(
            bfv_params,
            trbfv_params,
            self.sample_type,
            ciphernodes_config,
            self.security_parameter,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        // Calculate bit_msg for commitment computation
        // Use a reasonable default based on plaintext modulus
        let plaintext_modulus = bfv_params.plaintext();
        let bit_msg = calculate_bit_width(&plaintext_modulus.to_string())?;

        // Use the honest_ciphertexts directly
        let honest_cts: &[Vec<Ciphertext>] = &decryption_data.honest_ciphertexts;

        let vectors = DecBfvVectors::compute(
            honest_cts,
            &decryption_data.secret_key,
            bfv_params,
            trbfv_params,
            bit_msg,
        )?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        // Get number of honest parties from vectors
        let num_honest_parties = vectors_standard.decrypted_shares.len();

        // Determine sample type postfix
        let sample_type_postfix = match self.sample_type {
            SampleType::SecretKey => "SK",
            SampleType::SmudgingNoise => "E_SM",
        };

        let template_params = DecBfvTemplateParams::from_bounds(
            shared::template::BaseTemplateParams::new(
                bfv_params.degree(),
                trbfv_params.moduli().len(), // L is number of TRBFV moduli
                self.name(),
            ),
            num_honest_parties,
            bit_msg,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
            sample_type_postfix.to_string(),
        )?;

        // Generate config .nr file (named after parameter set: bfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        DecBfvConfigsGenerator::generate_configs_file(
            &template_params,
            output_dir,
            &configs_filename,
        )?;

        // Create TOML generator and generate file
        let toml_generator = DecBfvTomlGenerator::new(vectors_standard);
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
        let circuit = DecBfvCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
        assert_eq!(circuit.name(), "dec-bfv");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Bfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit = DecBfvCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
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
        assert!(content.contains("expected_commitments"));
        assert!(content.contains("decrypted_shares"));

        // Verify config file was generated (named after parameter set)
        let configs_path = temp_dir.path().join("bfv.nr");
        assert!(
            configs_path.exists(),
            "Config file bfv.nr should be created"
        );
        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        assert!(configs_content.contains("DEC_BFV_BIT_MSG"));
        assert!(configs_content.contains("N: u32"));
        assert!(configs_content.contains("L_TRBFV: u32"));
    }
}
