use crate::bounds::PkAggTrBfvCryptographicParameters;
use crate::configs::PkAggTrBfvConfigsGenerator;
use crate::sample::generate_sample_pk_aggregation;
use crate::template::PkAggTrBfvTemplateParams;
use crate::toml::PkAggTrBfvTomlGenerator;
use crate::vectors::PkAggTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::template::BaseTemplateParams;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

shared::circuit_struct!(PkAggTrBfvCircuit);

impl PkAggTrBfvCircuit {
    /// Create a new PkAggTrBfvCircuit with the specified parameter type and security parameter
    pub fn new(parameter_type: ParameterType, lambda: usize) -> Self {
        Self {
            parameter_type,
            security_parameter: lambda,
        }
    }
}

impl Circuit for PkAggTrBfvCircuit {
    fn name(&self) -> &'static str {
        "pk-agg-trbfv"
    }

    fn description(&self) -> &'static str {
        "TRBFV Public Key Aggregation zero-knowledge proof circuit for verifying correct aggregation of public keys from honest parties"
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
        // This circuit uses TRBFV parameters
        let selected_params = trbfv_params;

        // Generate bounds and cryptographic parameters
        let crypto_params = PkAggTrBfvCryptographicParameters {
            moduli: selected_params.moduli().to_vec(),
        };

        // Generate sample public key aggregation data
        let aggregation_data = generate_sample_pk_aggregation(selected_params, ciphernodes_config)
            .map_err(|e| shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            })?;

        // Compute witness vectors from the aggregation data
        let vectors = PkAggTrBfvVectors::compute(&aggregation_data, selected_params)?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
        let security_level = if self.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
            "production"
        } else {
            "insecure"
        };

        let template_params = PkAggTrBfvTemplateParams::new(
            BaseTemplateParams::new(
                selected_params.degree(),
                selected_params.moduli().len(),
                self.name(),
            ),
            aggregation_data.num_honest_parties,
            self.parameter_type().as_str().to_string(),
            security_level.to_string(),
        );

        // Generate config .nr file (named after parameter set: trbfv.nr)
        let configs_filename = format!("{}.nr", self.parameter_type().as_str());
        PkAggTrBfvConfigsGenerator::generate_configs_file(
            &crypto_params,
            &template_params,
            output_dir,
            &configs_filename,
            self.parameter_type().as_str(),
        )?;

        // Create TOML generator and generate file
        let toml_generator = PkAggTrBfvTomlGenerator::new(vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
