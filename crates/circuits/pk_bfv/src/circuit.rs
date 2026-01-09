use crate::bounds::PkBfvBounds;
use crate::configs::PkBfvConfigsGenerator;
use crate::sample::generate_sample_encryption;
use crate::template::PkBfvBoundsData;
use crate::toml::PkBfvTomlGenerator;
use crate::vectors::PkBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::ParameterType;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

shared::circuit_struct!(PkBfvCircuit);

impl PkBfvCircuit {
    /// Create a new PkBfvCircuit with the specified parameter type and security parameter
    pub fn new(parameter_type: ParameterType, lambda: usize) -> Self {
        Self {
            parameter_type,
            security_parameter: lambda,
        }
    }
}

impl Circuit for PkBfvCircuit {
    fn name(&self) -> &'static str {
        "pk-bfv"
    }

    fn description(&self) -> &'static str {
        "BFV Public Key commitment zero-knowledge proof circuit for BFV homomorphic public key"
    }

    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    fn security_parameter(&self) -> usize {
        self.security_parameter
    }

    fn generate_toml(
        &self,
        _trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        _ciphernodes_config: Option<&shared::circuit::CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        let selected_params = bfv_params;

        // Generate bounds and vectors directly for BFV Public Key
        let (crypto_params, bounds) = PkBfvBounds::compute(selected_params, 0)?;
        let encryption_data = generate_sample_encryption(bfv_params).map_err(|e| {
            shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            }
        })?;

        let vectors: PkBfvVectors =
            PkBfvVectors::compute(&encryption_data.public_key, selected_params)?;

        let vectors_standard = vectors.standard_form();

        // Generate template params for config file generation
        let bounds_data = PkBfvBoundsData {
            pk_bound: bounds.pk_bound.to_string(),
        };

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        let template_params = crate::template::PkBfvTemplateParams::from_bounds(
            shared::template::BaseTemplateParams::new(
                selected_params.degree(),
                selected_params.moduli().len(),
                self.name(),
            ),
            &bounds_data,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
        )?;

        // Generate config .nr file (named after parameter set: bfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        PkBfvConfigsGenerator::generate_configs_file(
            &crypto_params,
            &bounds,
            &template_params,
            output_dir,
            &configs_filename,
            self.parameter_type().as_str(),
        )?;

        // Create TOML generator and generate file (without params - they're in the config file)
        let toml_generator = PkBfvTomlGenerator::new(vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
