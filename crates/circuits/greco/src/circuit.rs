use crate::bounds::GrecoBounds;
use crate::sample::generate_sample_encryption;
use crate::toml::GrecoTomlGenerator;
use crate::vectors::GrecoVectors;
use fhe::bfv::BfvParameters;
use pvw::PvwParameters;
use shared::toml::TomlGenerator;
use shared::{Circuit, SupportedParameterType};
use std::path::Path;
use std::sync::Arc;

/// Greco circuit implementation
///
/// This struct implements the `Circuit` trait for the Greco zero-knowledge
/// proof circuit. It provides methods for parameter generation, TOML file
/// creation, and configuration validation.
///
/// The Greco circuit is designed to prove the correctness of BFV homomorphic
/// encryption without revealing the secret key or plaintext. It achieves this
/// by generating bounds and validation vectors that can be used in zero-knowledge
/// proofs.
pub struct GrecoCircuit;

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

    /// Returns the parameter types supported by the Greco circuit
    ///
    /// Greco only supports BFV parameters since it's specifically designed
    /// for proving BFV homomorphic encryption correctness.
    fn supported_parameter_types(&self) -> SupportedParameterType {
        SupportedParameterType::Bfv
    }

    fn generate_params(
        &self,
        _bfv_params: &Arc<BfvParameters>,
        _pvw_params: Option<&Arc<PvwParameters>>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Nothing to do - parameters are generated on-demand in generate_toml
        Ok(())
    }

    fn generate_toml(
        &self,
        bfv_params: &Arc<BfvParameters>,
        _pvw_params: Option<&Arc<PvwParameters>>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate bounds and vectors directly
        let (crypto_params, bounds) = GrecoBounds::compute(bfv_params, 0)?;

        let encryption_data = generate_sample_encryption(bfv_params).map_err(|e| {
            shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            }
        })?;

        let vectors = GrecoVectors::compute(
            &encryption_data.plaintext,
            &encryption_data.u_rns,
            &encryption_data.e0_rns,
            &encryption_data.e1_rns,
            &encryption_data.ciphertext,
            &encryption_data.public_key,
            bfv_params,
        )?;

        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = GrecoTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
