//! BFV Decryption circuit (no homomorphic addition) implementation
//!
//! This module provides the circuit interface for the dec_bfv_no_hom_add circuit,
//! which proves correct BFV decryption of encrypted TRBFV secret key shares
//! without homomorphic addition.

use crate::bounds::DecBfvNoHomAddBounds;
use crate::configs::DecBfvNoHomAddConfigsGenerator;
use crate::sample::generate_sample_decryption_no_hom_add;
use crate::template::{
    DecBfvNoHomAddBoundsData, DecBfvNoHomAddMainTemplate, DecBfvNoHomAddTemplateParams,
};
use crate::toml::DecBfvNoHomAddTomlGenerator;
use crate::vectors::DecBfvNoHomAddVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
use shared::template::MainTemplateGenerator;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// BFV Decryption circuit (no homomorphic addition) implementation
///
/// This circuit proves correct decryption of BFV ciphertexts containing
/// encrypted TRBFV secret key shares. It verifies:
/// 1. BFV decryption of H*L ciphertexts (H honest parties * L TRBFV bases)
/// 2. Each ciphertext decrypts using L' BFV RNS bases
/// 3. CRT reconstruction for each ciphertext to u_global
/// 4. Decoding each u_global to decrypted_share
/// 5. For each TRBFV basis l: sum_h decrypted_shares[h][l] mod trbfv_qi[l] = expected_share[l]
pub struct DecBfvNoHomAddCircuit {
    /// The parameter type (always BFV for this circuit)
    pub parameter_type: ParameterType,
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

impl DecBfvNoHomAddCircuit {
    /// Create a new DecBfvNoHomAddCircuit instance with the specified sample type and security parameter
    ///
    /// # Arguments
    ///
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    /// * `lambda` - The security parameter (λ)
    pub fn new(sample_type: SampleType, lambda: usize) -> Self {
        DecBfvNoHomAddCircuit {
            parameter_type: ParameterType::Bfv,
            sample_type,
            security_parameter: lambda,
        }
    }
}

impl Default for DecBfvNoHomAddCircuit {
    fn default() -> Self {
        Self::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA) // Default to insecure lambda for testing
    }
}

impl Circuit for DecBfvNoHomAddCircuit {
    /// Returns the name of the BFV decryption circuit (no homomorphic addition)
    fn name(&self) -> &'static str {
        "dec-bfv-no-hom-add"
    }

    /// Returns a description of the circuit
    fn description(&self) -> &'static str {
        "Zero-knowledge proof circuit for BFV decryption of encrypted TRBFV shares (no homomorphic addition)"
    }

    /// Returns the parameter type this circuit uses
    fn parameter_type(&self) -> ParameterType {
        ParameterType::Bfv // Uses BFV parameters
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
        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = DecBfvNoHomAddBounds::compute(bfv_params, trbfv_params, 0)?;

        // Generate sample decryption data
        let decryption_data = generate_sample_decryption_no_hom_add(
            bfv_params,
            trbfv_params,
            self.sample_type,
            ciphernodes_config,
            self.security_parameter,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        // Compute witness vectors from the decryption data
        // Calculate bit_sk for commitment computation
        let bit_sk = shared::template::calculate_bit_width(&bounds.s_bound.to_string())?;

        let vectors = DecBfvNoHomAddVectors::compute(
            &decryption_data.honest_ciphertexts,
            &decryption_data.secret_key,
            bfv_params,
            trbfv_params,
            bit_sk,
            crypto_params.bfv_q_inverse_mod_t,
        )?;

        // Verify all circuit constraints in Rust before generating TOML
        // This ensures the generated witness data is valid
        vectors.verify(bfv_params, trbfv_params)?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Generate template params for config file generation
        let bounds_data = DecBfvNoHomAddBoundsData {
            s_bound: bounds.s_bound.to_string(),
            u_i_bounds: bounds.u_i_bounds.iter().map(|b| b.to_string()).collect(),
            u_global_bound: bounds.u_global_bound.to_string(),
            r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
            r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
            delta: bounds.delta.to_string(),
            delta_half: bounds.delta_half.to_string(),
        };

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        // Get number of honest parties from vectors
        let num_honest_parties = vectors_standard.honest_c0.len();
        let num_trbfv_bases = trbfv_params.moduli().len();
        let num_bfv_bases = bfv_params.moduli().len();

        let template_params = DecBfvNoHomAddTemplateParams::from_bounds(
            shared::template::BaseTemplateParams::new(
                bfv_params.degree(),
                num_trbfv_bases,
                self.name(),
            ),
            num_honest_parties,
            num_trbfv_bases,
            num_bfv_bases,
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
        )?;

        // Generate config .nr file (named after parameter set: bfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        DecBfvNoHomAddConfigsGenerator::generate_configs_file(
            &crypto_params,
            &bounds,
            &template_params,
            output_dir,
            &configs_filename,
            self.parameter_type().as_str(),
        )?;

        // Generate main.nr template
        let template_generator = DecBfvNoHomAddMainTemplate;
        let template_content = template_generator.generate_template(&template_params)?;
        let template_path = output_dir.join("main.nr");
        std::fs::write(&template_path, template_content)?;

        // Create TOML generator and generate file (without params - they're in the config file)
        let toml_generator = DecBfvNoHomAddTomlGenerator::new(vectors_standard);
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
        let circuit =
            DecBfvNoHomAddCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
        assert_eq!(circuit.name(), "dec-bfv-no-hom-add");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Bfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit =
            DecBfvNoHomAddCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
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
        // Note: crypto and bounds are in a separate config file, not in Prover.toml
        let content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("honest_c0"));
        assert!(content.contains("expected_aggregated_shares"));

        // Verify config file was generated (named after parameter set)
        let configs_path = temp_dir.path().join("bfv.nr");
        assert!(
            configs_path.exists(),
            "Config file bfv.nr should be created"
        );
        let configs_content = std::fs::read_to_string(&configs_path).unwrap();
        assert!(configs_content.contains("DEC_BFV_CONFIGS"));
        assert!(configs_content.contains("N: u32"));
        assert!(configs_content.contains("L: u32"));
        assert!(configs_content.contains("L_PRIME: u32"));
        // H is declared in the template, not in the configs file

        // Verify main.nr template was generated
        let template_path = temp_dir.path().join("main.nr");
        assert!(template_path.exists(), "main.nr template should be created");
        let template_content = std::fs::read_to_string(&template_path).unwrap();
        assert!(template_content.contains("BfvDecNoHomAdd"));
        assert!(template_content.contains("expected_sk_commitment"));
    }

    #[test]
    fn test_toml_generation_with_custom_config() {
        let circuit =
            DecBfvNoHomAddCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
        let params = test_parameters_bfv();
        let temp_dir = TempDir::new().unwrap();

        let config = CiphernodesConfig::new(5, 5, 2);
        let result = circuit.generate_toml(&params, &params, temp_dir.path(), Some(&config));
        assert!(
            result.is_ok(),
            "TOML generation with custom config should succeed: {:?}",
            result.err()
        );

        // Verify the file was created
        let toml_path = temp_dir.path().join("Prover.toml");
        assert!(toml_path.exists(), "Prover.toml should be created");
    }
}
