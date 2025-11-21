use crate::bounds::DecShareAggTrBfvBounds;
use crate::sample::generate_sample_decryption_share_aggregation;
use crate::toml::DecShareAggTrBfvTomlGenerator;
use crate::vectors::DecShareAggTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;
shared::circuit_struct!(DecShareAggTrBfvCircuit);

impl Circuit for DecShareAggTrBfvCircuit {
    fn name(&self) -> &'static str {
        "dec-share-agg-trbfv"
    }

    fn description(&self) -> &'static str {
        "Decryption Share Aggregation TRBFV zero-knowledge proof circuit"
    }

    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        _bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate sample decryption share aggregation data
        let decryption_data =
            generate_sample_decryption_share_aggregation(trbfv_params, ciphernodes_config)
                .map_err(|e| shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                })?;

        let (crypto_params, bounds) =
            DecShareAggTrBfvBounds::compute(trbfv_params, 0).map_err(|e| {
                shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                }
            })?;

        let vectors = DecShareAggTrBfvVectors::compute(
            &decryption_data.d_share_polys,
            &decryption_data.party_ids,
            &decryption_data.message,
            trbfv_params,
            decryption_data.threshold,
            decryption_data.num_parties,
        )?;

        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator =
            DecShareAggTrBfvTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
