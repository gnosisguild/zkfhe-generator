//! Verify Shares TRBFV circuit implementation
//!
//! This module provides the circuit interface for the verify-shares-trbfv circuit,
//! which verifies that Shamir secret key shares satisfy the Reed-Solomon parity check.

use crate::bounds::VerifySharesTrbfvBounds;
use crate::configs::VerifySharesTrbfvConfigsGenerator;
use crate::sample::generate_sample_sk_shares;
use crate::template::{VerifySharesTrbfvBoundsData, VerifySharesTrbfvTemplateParams};
use crate::toml::VerifySharesTrbfvTomlGenerator;
use crate::vectors::VerifySharesTrbfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// Verify Shares TRBFV circuit implementation
///
/// This circuit verifies that Shamir secret shares satisfy the Reed-Solomon parity check.
/// The secret can be either sk_trbfv or e_sm (smudging noise).
/// It verifies:
/// 1. secret consistency: y[i][j][0] == secret[i] for all i, j
/// 2. Range checks: secret coefficients are trinary {-1, 0, 1}, shares are in [0, q_j)
/// 3. Parity check: H[j] * y[i][j]^T == 0 mod q_j for all i, j
/// 4. Secret commitment matches expected commitment (from C1)
pub struct VerifySharesTrbfvCircuit {
    /// The parameter type this circuit is configured with
    pub parameter_type: ParameterType,
    /// The sample type to use for share generation
    ///
    /// This determines whether to generate sk_sss (SecretKey) or
    /// es_sss (SmudgingNoise) shares when creating sample data.
    pub sample_type: SampleType,
    /// The security parameter (λ) this circuit is configured with
    ///
    /// This value is explicitly stored and can be used for fhe.rs function calls
    /// that require the security parameter. Parameters are considered secure
    /// if lambda >= 80, and insecure if lambda < 80.
    pub security_parameter: usize,
}

impl VerifySharesTrbfvCircuit {
    /// Create a new VerifySharesTrbfvCircuit instance with the specified parameter type, sample type, and security parameter
    ///
    /// # Arguments
    ///
    /// * `parameter_type` - The parameter type (Trbfv or Bfv)
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    /// * `lambda` - The security parameter (λ)
    pub fn new(parameter_type: ParameterType, sample_type: SampleType, lambda: usize) -> Self {
        VerifySharesTrbfvCircuit {
            parameter_type,
            sample_type,
            security_parameter: lambda,
        }
    }
}

impl Circuit for VerifySharesTrbfvCircuit {
    /// Returns the name of the Verify Shares TRBFV circuit
    fn name(&self) -> &'static str {
        "verify-shares-trbfv"
    }

    /// Returns a description of the Verify Shares TRBFV circuit
    fn description(&self) -> &'static str {
        "Zero-knowledge proof circuit for verifying that Shamir secret key shares satisfy the Reed-Solomon parity check"
    }

    /// Returns the parameter type this circuit uses
    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn security_parameter(&self) -> usize {
        self.security_parameter
    }

    /// Generate TOML file with sample data and parameters
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        _bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // verify-shares-trbfv uses TRBFV parameters
        let selected_params = trbfv_params;

        // Generate bounds and cryptographic parameters
        // For smudging noise, we need to compute the smudging bound
        let (crypto_params, bounds) = if matches!(self.sample_type, SampleType::SmudgingNoise) {
            let config = ciphernodes_config
                .cloned()
                .unwrap_or_else(|| shared::circuit::CiphernodesConfig::new(5, 5, 2));
            let num_ciphertexts = 1; // we only need one ciphertext for the secret commitment
            VerifySharesTrbfvBounds::compute_with_smudging(
                selected_params,
                0,
                self.security_parameter,
                &config,
                num_ciphertexts,
            )?
        } else {
            VerifySharesTrbfvBounds::compute(selected_params, 0)?
        };

        // Calculate bit_secret from the appropriate bound for commitment computation
        // Use smudging bound if available, otherwise use sk_bound
        let secret_bound = bounds.e_sm_bound.as_ref().unwrap_or(&bounds.sk_bound);
        let bit_secret = shared::template::calculate_bit_width(&secret_bound.to_string())?;

        // Generate sample secret shares data (can be either secret key or smudging noise)
        let shares_data = generate_sample_sk_shares(
            selected_params,
            self.sample_type,
            ciphernodes_config,
            self.security_parameter,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        // Compute witness vectors from the shares data
        let vectors = VerifySharesTrbfvVectors::compute(&shares_data, selected_params, bit_secret)?;

        // Verify that vectors satisfy circuit constraints
        vectors.verify(
            selected_params,
            shares_data.num_parties,
            shares_data.threshold,
        )?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Generate template params for constant file generation
        // Use the actual secret bound for bit_secret calculation (smudging bound if available, otherwise sk_bound)
        let secret_bound_str = bounds
            .e_sm_bound
            .as_ref()
            .map(|b| b.to_string())
            .unwrap_or_else(|| bounds.sk_bound.to_string());
        let bounds_data = VerifySharesTrbfvBoundsData {
            sk_bound: bounds.sk_bound.to_string(),
            secret_bound: secret_bound_str,
            moduli: crypto_params.moduli.clone(),
        };

        let config = ciphernodes_config
            .cloned()
            .unwrap_or_else(|| shared::circuit::CiphernodesConfig::new(5, 5, 2));

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        let mut template_params = VerifySharesTrbfvTemplateParams::from_bounds(
            shared::template::BaseTemplateParams::new(
                selected_params.degree(),
                selected_params.moduli().len(),
                self.name(),
            ),
            config.num_parties,
            config.threshold,
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
        )?;

        // Set the secret type postfix based on sample type
        template_params.secret_type_postfix = match self.sample_type {
            SampleType::SecretKey => "SK".to_string(),
            SampleType::SmudgingNoise => "E_SM".to_string(),
        };

        // Calculate bit widths for both secret types
        let bit_sk = shared::template::calculate_bit_width(&bounds.sk_bound.to_string())?;
        let bit_esm = bounds
            .e_sm_bound
            .as_ref()
            .map(|b| shared::template::calculate_bit_width(&b.to_string()))
            .transpose()?
            .unwrap_or(bit_sk); // Fallback to sk if no esm bound

        // Generate single config file with both SK and ESM bit parameters
        let param_type_str = self.parameter_type().as_str();
        let configs_filename = format!("{}.nr", param_type_str);
        let content = VerifySharesTrbfvConfigsGenerator::generate_configs_with_both_secret_types(
            &crypto_params,
            &template_params,
            bit_sk,
            bit_esm,
        )?;
        std::fs::write(output_dir.join(&configs_filename), content)?;

        // Create TOML generator and generate file (without params - they're in the config file)
        let toml_generator = VerifySharesTrbfvTomlGenerator::new(vectors_standard);
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
        let circuit = VerifySharesTrbfvCircuit::new(
            ParameterType::Trbfv,
            SampleType::SecretKey,
            shared::DEFAULT_INSECURE_LAMBDA,
        );
        assert_eq!(circuit.name(), "verify-shares-trbfv");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Trbfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit = VerifySharesTrbfvCircuit::new(
            ParameterType::Trbfv,
            SampleType::SecretKey,
            shared::DEFAULT_INSECURE_LAMBDA,
        );
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
        // Note: params are now in a separate .nr constant file
        assert!(content.contains("secret_crt"));
        assert!(content.contains("expected_secret_commitment"));
        assert!(content.contains("y"));
        assert!(content.contains("h"));

        // Verify config file was generated (named after parameter set)
        let configs_path = temp_dir.path().join("trbfv.nr");
        assert!(
            configs_path.exists(),
            "trbfv.nr config file should be created"
        );
    }
}
