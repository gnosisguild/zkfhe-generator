use crate::bounds::PkAggTrBfvCryptographicParameters;
use crate::sample::generate_sample_pk_aggregation;
use crate::toml::PkAggTrBfvTomlGenerator;
use crate::vectors::PkAggTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
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

        // Verify that vectors satisfy circuit constraints before generating TOML
        // This ensures the generated witness data is valid
        vectors.verify(selected_params, aggregation_data.num_honest_parties)?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator = PkAggTrBfvTomlGenerator::new(crypto_params, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
