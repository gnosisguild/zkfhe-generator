use crate::bounds::DecShareTrBfvBounds;
use crate::configs::DecShareTrBfvConfigsGenerator;
use crate::sample::generate_sample_decryption_share;
use crate::template::{DecShareTrBfvBoundsData, DecShareTrBfvTemplateParams};
use crate::toml::DecShareTrBfvTomlGenerator;
use crate::vectors::DecShareTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::template::BaseTemplateParams;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;
shared::circuit_struct!(DecShareTrBfvCircuit);

impl DecShareTrBfvCircuit {
    /// Create a new DecShareTrBfvCircuit with the specified parameter type and security parameter
    pub fn new(parameter_type: ParameterType, lambda: usize) -> Self {
        Self {
            parameter_type,
            security_parameter: lambda,
        }
    }
}

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

    fn security_parameter(&self) -> usize {
        self.security_parameter
    }

    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate sample decryption share data
        let decryption_data = generate_sample_decryption_share(
            trbfv_params,
            bfv_params,
            ciphernodes_config,
            self.security_parameter,
        )
        .map_err(|e| shared::errors::ZkFheError::Bfv {
            message: e.to_string(),
        })?;

        let (crypto_params, bounds) =
            DecShareTrBfvBounds::compute(trbfv_params, 0).map_err(|e| {
                shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                }
            })?;

        // Create bounds data for template (needed for bit width calculation)
        let bounds_data = DecShareTrBfvBoundsData {
            decryption_share_bound: bounds.decryption_share_bound.to_string(),
            r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
            r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
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

        let template_params = DecShareTrBfvTemplateParams::from_bounds(
            BaseTemplateParams::new(
                trbfv_params.degree(),
                trbfv_params.moduli().len(),
                self.name(),
            ),
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
            num_parties as u32,
            threshold as u32,
        )?;

        // Extract bit_s and bit_e from template_params (they are both equal to bit_r2)
        let bit_s = template_params.bit_s;
        let bit_e = template_params.bit_e;

        let vectors = DecShareTrBfvVectors::compute(
            &decryption_data.ciphertext,
            &decryption_data.s_rns,
            &decryption_data.e_rns,
            &decryption_data.d_share_rns,
            trbfv_params,
            bit_s,
            bit_e,
        )?;

        let vectors_standard = vectors.standard_form();

        // Generate config .nr file (named after parameter set: trbfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        DecShareTrBfvConfigsGenerator::generate_configs_file(
            &crypto_params,
            &bounds,
            &template_params,
            output_dir,
            &configs_filename,
            self.parameter_type().as_str(),
        )?;

        // Create TOML generator and generate file
        let toml_generator = DecShareTrBfvTomlGenerator::new(vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
