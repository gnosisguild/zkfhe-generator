use crate::bounds::PkTrBfvBounds;
use crate::configs::PkTrBfvConfigsGenerator;
use crate::sample::generate_sample_encryption;
use crate::template::PkTrBfvBoundsData;
use crate::toml::PkTrBfvTomlGenerator;
use crate::vectors::PkTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

shared::circuit_struct!(PkTrBfvCircuit);

impl PkTrBfvCircuit {
    /// Create a new PkTrBfvCircuit with the specified parameter type and security parameter
    ///
    /// Note: This circuit now only supports TRBFV parameters.
    pub fn new(parameter_type: ParameterType, lambda: usize) -> Self {
        Self {
            parameter_type,
            security_parameter: lambda,
        }
    }
}

impl Circuit for PkTrBfvCircuit {
    fn name(&self) -> &'static str {
        "pk-trbfv"
    }

    fn description(&self) -> &'static str {
        "Public Key Threshold BFV zero-knowledge proof circuit for Threshold BFV homomorphic public key"
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
        let selected_params = trbfv_params;
        let lambda = self.security_parameter();

        // Get ciphernodes config for smudging bound calculation
        let config = ciphernodes_config
            .cloned()
            .unwrap_or_else(CiphernodesConfig::defaults);
        // Needed for smudging bound calculation (B_c)
        // We set it to 1 as we only need one ciphertext for public key generation
        let num_ciphertexts = 1;

        // Generate bounds and vectors directly for Threshold BFV Public Key
        let (crypto_params, bounds) =
            PkTrBfvBounds::compute(selected_params, 0, lambda, &config, num_ciphertexts)?;
        let encryption_data =
            generate_sample_encryption(trbfv_params, lambda, &config, num_ciphertexts).map_err(
                |e| shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                },
            )?;

        let vectors: PkTrBfvVectors = PkTrBfvVectors::compute(
            &encryption_data.a,
            &encryption_data.e_rns,
            &encryption_data.sk_rns,
            &encryption_data.e_sm_rns,
            &encryption_data.public_key,
            selected_params,
        )?;

        let vectors_standard = vectors.standard_form();

        // Generate template params for config file generation
        let bounds_data = PkTrBfvBoundsData {
            eek_bound: bounds.eek_bound.to_string(),
            sk_bound: bounds.sk_bound.to_string(),
            e_sm_bound: bounds.e_sm_bound.to_string(),
            r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
            r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
            pk_bound: bounds.pk_bound.to_string(),
        };

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        let template_params = crate::template::PkTrBfvTemplateParams::from_bounds(
            shared::template::BaseTemplateParams::new(
                selected_params.degree(),
                selected_params.moduli().len(),
                self.name(),
            ),
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
        )?;

        // Generate config .nr file (named after parameter set: trbfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        PkTrBfvConfigsGenerator::generate_configs_file(
            &crypto_params,
            &bounds,
            &template_params,
            output_dir,
            &configs_filename,
            self.parameter_type().as_str(),
        )?;

        // Create TOML generator and generate file (without params - they're in the config file)
        let toml_generator = PkTrBfvTomlGenerator::new(vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
