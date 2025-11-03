use crate::bounds::GrecoBounds;
use crate::sample::generate_sample_encryption;
use crate::toml::GrecoTomlGenerator;
use crate::vectors::GrecoVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::ParameterType;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;
shared::circuit_struct!(GrecoCircuit);

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
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate bounds and vectors directly
        let (crypto_params, bounds) = GrecoBounds::compute(bfv_params, 0)?;

        let encryption_data =
            generate_sample_encryption(bfv_params, self.parameter_type).map_err(|e| {
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
