//! BFV Encryption circuit implementation
//!
//! This module provides the circuit interface for the enc-bfv circuit,
//! which verifies correct BFV homomorphic encryption with message commitment verification.

use crate::bounds::EncBfvBounds;
use crate::configs::EncBfvConfigsGenerator;
use crate::sample::generate_sample_encryption;
use crate::template::{EncBfvBoundsData, EncBfvTemplateParams};
use crate::toml::EncBfvTomlGenerator;
use crate::vectors::EncBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// BFV Encryption circuit implementation
///
/// This circuit verifies correct BFV encryption operations with message commitment verification.
/// The message can be either sk shares (Circuit 3a) or e_sm shares (Circuit 3b).
/// It verifies:
/// 1. Public key commitment matches expected (from Circuit 0)
/// 2. Message commitment matches expected (from SK shares circuit)
/// 3. Correct BFV encryption: ct0[l] = pk0[l] * u + e0[l] + k1 * k0[l] + r1[l] * q[l] + r2[l] * (X^N + 1)
///    and ct1[l] = pk1[l] * u + e1 + p2[l] * (X^N + 1) + p1[l] * q[l]
pub struct EncBfvCircuit {
    /// The sample type to use for encryption
    ///
    /// This determines whether to encrypt sk shares (SecretKey) or
    /// e_sm shares (SmudgingNoise) when creating sample data.
    pub sample_type: SampleType,
    /// The security parameter (λ) this circuit is configured with
    ///
    /// This value is explicitly stored and can be used for fhe.rs function calls
    /// that require the security parameter. Parameters are considered secure
    /// if lambda >= 80, and insecure if lambda < 80.
    pub security_parameter: usize,
}

impl EncBfvCircuit {
    /// Create a new EncBfvCircuit with the specified sample type and security parameter
    ///
    /// # Arguments
    ///
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    /// * `lambda` - The security parameter (λ)
    pub fn new(sample_type: SampleType, lambda: usize) -> Self {
        EncBfvCircuit {
            sample_type,
            security_parameter: lambda,
        }
    }
}

impl Circuit for EncBfvCircuit {
    /// Returns the name of the BFV Encryption circuit
    fn name(&self) -> &'static str {
        "enc-bfv"
    }

    /// Returns a description of the BFV Encryption circuit
    fn description(&self) -> &'static str {
        "BFV Encryption zero-knowledge proof circuit for BFV homomorphic encryption with message commitment verification"
    }

    /// Returns the parameter type this circuit uses
    /// enc-bfv only supports BFV (not TRBFV)
    fn parameter_type(&self) -> ParameterType {
        ParameterType::Bfv
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
        // enc-bfv uses BFV parameters only
        let selected_params = bfv_params;

        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = EncBfvBounds::compute(selected_params, 0)?;

        // Generate sample encryption data
        // Use the sample_type to determine what to encrypt (sk shares or e_sm shares)
        let encryption_data = generate_sample_encryption(
            trbfv_params,
            bfv_params,
            self.sample_type,
            ciphernodes_config,
            self.security_parameter,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        // Calculate bit_pk from bounds for commitment computation
        let bit_pk = shared::template::calculate_bit_width(&bounds.pk_bounds[0].to_string())?;

        // Compute witness vectors from the encryption data
        let vectors = EncBfvVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            selected_params,
            bit_pk,
        )?;

        let vectors_standard = vectors.standard_form();

        // Generate template params for config file generation
        let bounds_data = EncBfvBoundsData {
            t: crypto_params.t.to_string(),
            q_mod_t: crypto_params.q_mod_t.to_string(),
            moduli: crypto_params.moduli.clone(),
            k0is: crypto_params.k0is.clone(),
            u_bound: bounds.u_bound.to_string(),
            e0_bound: bounds.e0_bound.to_string(),
            e1_bound: bounds.e1_bound.to_string(),
            msg_bound: bounds.msg_bound.to_string(),
            pk_bounds: bounds.pk_bounds.iter().map(|b| b.to_string()).collect(),
            r1_low_bounds: bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect(),
            r1_up_bounds: bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect(),
            r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
            p1_bounds: bounds.p1_bounds.iter().map(|b| b.to_string()).collect(),
            p2_bounds: bounds.p2_bounds.iter().map(|b| b.to_string()).collect(),
        };

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        // Determine sample_type_postfix based on sample_type
        let sample_type_postfix = match self.sample_type {
            SampleType::SecretKey => "SK",
            SampleType::SmudgingNoise => "E_SM",
        };

        let template_params = EncBfvTemplateParams::from_bounds(
            shared::template::BaseTemplateParams::new(
                selected_params.degree(),
                selected_params.moduli().len(),
                self.name(),
            ),
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
            sample_type_postfix.to_string(),
        )?;

        // Generate config .nr file (named after parameter set: bfv.nr)
        // Generate configs with both SK and E_SM variants
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        let configs_content = EncBfvConfigsGenerator::generate_configs_with_both_sample_types(
            &crypto_params,
            &bounds,
            &template_params,
            self.parameter_type().as_str(),
        )?;
        let configs_path = output_dir.join(&configs_filename);
        std::fs::write(&configs_path, configs_content)?;

        // Create TOML generator and generate file (without params - they're in the config file)
        let toml_generator = EncBfvTomlGenerator::new(vectors_standard);
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
        let circuit = EncBfvCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
        assert_eq!(circuit.name(), "enc-bfv");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Bfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit = EncBfvCircuit::new(SampleType::SecretKey, shared::DEFAULT_INSECURE_LAMBDA);
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
        // Note: params are now in a separate .nr constant file
        assert!(content.contains("expected_pk_commitment"));
        assert!(content.contains("expected_message_commitment"));
        assert!(content.contains("pk0is"));
        assert!(content.contains("ct0is"));
        assert!(content.contains("message"));

        // Verify config file was generated (named after parameter set)
        let configs_path = temp_dir.path().join("bfv.nr");
        assert!(
            configs_path.exists(),
            "bfv.nr config file should be created"
        );
    }
}
