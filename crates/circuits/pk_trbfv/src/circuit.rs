use crate::bounds::PkTrBfvBounds;
use crate::sample::generate_sample_encryption;
use crate::toml::PkTrBfvTomlGenerator;
use crate::vectors::PkTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

shared::circuit_struct!(PkTrBfvCircuit);

impl Circuit for PkTrBfvCircuit {
    fn name(&self) -> &'static str {
        "pk-trbfv"
    }

    fn description(&self) -> &'static str {
        "Public Key TRBFV zero-knowledge proof circuit for BFV homomorphic public key"
    }

    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        _ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        let selected_params = if self.parameter_type == ParameterType::Trbfv {
            trbfv_params
        } else {
            bfv_params
        };

        // Generate bounds and vectors directly
        let (crypto_params, bounds) = PkTrBfvBounds::compute(selected_params, 0)?;
        let encryption_data =
            generate_sample_encryption(trbfv_params, bfv_params, self.parameter_type).map_err(
                |e| shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                },
            )?;

        let vectors: PkTrBfvVectors = PkTrBfvVectors::compute(
            &encryption_data.a,
            &encryption_data.e_rns,
            &encryption_data.sk_rns,
            &encryption_data.public_key,
            selected_params,
        )?;

        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = PkTrBfvTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
