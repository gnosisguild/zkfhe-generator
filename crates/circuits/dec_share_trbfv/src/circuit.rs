use crate::bounds::DecShareTrBfvBounds;
use crate::sample::generate_sample_decryption_share;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

pub struct DecShareTrBfvCircuit;

impl Circuit for DecShareTrBfvCircuit {
    fn name(&self) -> &'static str {
        "dec-share-trbfv"
    }

    fn description(&self) -> &'static str {
        "Decryption share TRBFV zero-knowledge proof circuit"
    }

    fn generate_toml(
        &self,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate sample decryption share data
        let decryption_data = generate_sample_decryption_share(bfv_params).map_err(|e| {
            shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            }
        })?;

        /// TODO
        Ok(())
    }
}
