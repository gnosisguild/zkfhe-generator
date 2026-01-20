use crate::bounds::DecSharesAggTrBfvBounds;
use crate::configs::DecSharesAggTrBfvConfigsGenerator;
use crate::sample::generate_sample_decryption_share_aggregation;
use crate::template::{DecSharesAggTrBfvBoundsData, DecSharesAggTrBfvTemplateParams};
use crate::toml::DecSharesAggTrBfvTomlGenerator;
use crate::vectors::DecSharesAggTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::template::BaseTemplateParams;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;
shared::circuit_struct!(DecSharesAggTrBfvCircuit);

impl DecSharesAggTrBfvCircuit {
    /// Create a new DecSharesAggTrBfvCircuit with the specified parameter type and security parameter
    pub fn new(parameter_type: ParameterType, lambda: usize) -> Self {
        Self {
            parameter_type,
            security_parameter: lambda,
        }
    }
}

impl Circuit for DecSharesAggTrBfvCircuit {
    fn name(&self) -> &'static str {
        "dec-shares-agg-trbfv"
    }

    fn description(&self) -> &'static str {
        "Decryption Share Aggregation TRBFV zero-knowledge proof circuit"
    }

    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn security_parameter(&self) -> usize {
        self.security_parameter
    }

    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        _bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate sample decryption share aggregation data
        let decryption_data = generate_sample_decryption_share_aggregation(
            trbfv_params,
            ciphernodes_config,
            self.security_parameter,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        let (crypto_params, bounds) =
            DecSharesAggTrBfvBounds::compute(trbfv_params, 0).map_err(|e| {
                shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                }
            })?;

        let vectors = DecSharesAggTrBfvVectors::compute(
            &decryption_data.d_share_polys,
            &decryption_data.party_ids,
            &decryption_data.message,
            trbfv_params,
            decryption_data.threshold,
            decryption_data.num_parties,
        )?;

        let vectors_standard = vectors.standard_form();

        // Trim vectors based on non-zero message coefficients

        let nonzero_count = vectors_standard.count_nonzero_message_coefficients();

        let vectors_trimmed = vectors_standard.trim_to_nonzero(nonzero_count);

        println!(
            "📊 Trimming vectors to {} non-zero message coefficients",
            nonzero_count
        );

        // Create bounds data for template
        let bounds_data = DecSharesAggTrBfvBoundsData {
            delta: bounds.delta.to_string(),
            delta_half: bounds.delta_half.to_string(),
        };

        // Get num_parties and threshold from config or use defaults
        let config = ciphernodes_config
            .cloned()
            .unwrap_or_else(CiphernodesConfig::defaults);
        let num_parties = config.num_parties;
        let threshold = config.threshold;

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        let template_params = DecSharesAggTrBfvTemplateParams::from_bounds(
            BaseTemplateParams::new(nonzero_count, trbfv_params.moduli().len(), self.name()),
            threshold as u32,
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
            num_parties as u32,
        )?;

        // Generate config .nr file (named after parameter set: trbfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        DecSharesAggTrBfvConfigsGenerator::generate_configs_file(
            &crypto_params,
            &template_params,
            output_dir,
            &configs_filename,
            self.parameter_type().as_str(),
        )?;

        // Create TOML generator and generate file
        let toml_generator = DecSharesAggTrBfvTomlGenerator::new(vectors_trimmed);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
