use crate::bounds::DecShareTrBfvBounds;
use crate::sample::generate_sample_decryption_share;
use crate::toml::DecShareTrBfvTomlGenerator;
use crate::vectors::DecShareTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;
shared::circuit_struct!(DecShareTrBfvCircuit);

impl Circuit for DecShareTrBfvCircuit {
    fn name(&self) -> &'static str {
        "dec-share-trbfv"
    }

    fn description(&self) -> &'static str {
        "Decryption share TRBFV zero-knowledge proof circuit"
    }

    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate sample decryption share data
        let decryption_data =
            generate_sample_decryption_share(trbfv_params, bfv_params, ciphernodes_config)
                .map_err(|e| shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                })?;

        let (crypto_params, bounds) =
            DecShareTrBfvBounds::compute(trbfv_params, 0).map_err(|e| {
                shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                }
            })?;

        let vectors = DecShareTrBfvVectors::compute(
            &decryption_data.ciphertext,
            &decryption_data.s_rns,
            &decryption_data.e_rns,
            &decryption_data.d_share_rns,
            trbfv_params,
        )?;

        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator =
            DecShareTrBfvTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
