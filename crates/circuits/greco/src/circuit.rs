use crate::bounds::GrecoBounds;
use crate::sample::generate_sample_encryption;
use crate::toml::GrecoTomlGenerator;
use crate::vectors::GrecoVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{ParameterType, SampleType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// Greco circuit implementation
///
/// This struct holds the configuration for the Greco circuit, including
/// the parameter type and sample type for share_row generation.
pub struct GrecoCircuit {
    /// The parameter type this circuit is configured with
    pub parameter_type: ParameterType,
    /// The sample type to use for share_row generation
    ///
    /// This determines whether to generate sk_sss (SecretKey) or
    /// es_sss (SmudgingNoise) share_row when creating sample encryption data.
    pub sample_type: SampleType,
}

impl GrecoCircuit {
    /// Create a new GrecoCircuit with the specified parameter type and sample type
    ///
    /// # Arguments
    ///
    /// * `parameter_type` - The parameter type (BFV or trBFV)
    /// * `sample_type` - The sample type (SecretKey or SmudgingNoise)
    pub fn new(parameter_type: ParameterType, sample_type: SampleType) -> Self {
        GrecoCircuit {
            parameter_type,
            sample_type,
        }
    }
}

impl Circuit for GrecoCircuit {
    /// Returns the name of the Greco circuit
    ///
    /// This name is used in CLI commands and error messages to identify
    /// the circuit implementation.
    fn name(&self) -> &'static str {
        "greco"
    }

    /// Returns a description of the Greco circuit
    ///
    /// This description provides information about what the circuit does
    /// and its intended use case.
    fn description(&self) -> &'static str {
        "Greco zero-knowledge proof circuit for BFV homomorphic encryption"
    }

    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        let selected_params = if self.parameter_type == ParameterType::Trbfv {
            trbfv_params
        } else {
            bfv_params
        };

        // Generate bounds and vectors directly
        let (crypto_params, bounds) = GrecoBounds::compute(selected_params, 0)?;

        let encryption_data = generate_sample_encryption(
            trbfv_params,
            bfv_params,
            self.parameter_type,
            self.sample_type,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        let vectors = GrecoVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            selected_params,
        )?;

        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = GrecoTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
