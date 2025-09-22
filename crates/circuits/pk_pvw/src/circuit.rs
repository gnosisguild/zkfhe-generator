use crate::bounds::PkPvwBounds;
use crate::sample::generate_sample_pvw_data;
use crate::toml::{PkPvwTomlGenerator, CircuitParams};
use crate::vectors::PkPvwVectors;
use fhe::bfv::BfvParameters;
use pvw::PvwParameters;
use shared::toml::TomlGenerator;
use shared::{Circuit, SupportedParameterType};
use std::path::Path;
use std::sync::Arc;

pub struct PkPvwCircuit;

impl Circuit for PkPvwCircuit {
    fn name(&self) -> &'static str {
        "pk_pvw"
    }

    fn description(&self) -> &'static str {
        "PK PVW circuit for zero-knowledge FHE proofs"
    }

    fn supported_parameter_types(&self) -> SupportedParameterType {
        SupportedParameterType::Pvw
    }

    fn generate_params(
        &self,
        _bfv_params: &Arc<BfvParameters>,
        _pvw_params: Option<&Arc<PvwParameters>>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Nothing to do - parameters are generated on-demand in generate_toml
        Ok(())
    }

    fn generate_toml(
        &self,
        _bfv_params: &Arc<BfvParameters>,
        pvw_params: Option<&Arc<PvwParameters>>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        let pvw_params = pvw_params.ok_or_else(|| shared::errors::ZkFheError::Bfv {
            message: "PVW parameters are required for pk_pvw circuit".to_string(),
        })?;

        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = PkPvwBounds::compute(pvw_params, 0)?;

        // Generate sample PVW encryption data
        let encryption_data =
            generate_sample_pvw_data(pvw_params).map_err(|e| shared::errors::ZkFheError::Bfv {
                message: format!("Failed to generate sample PVW data: {e}"),
            })?;

        // Compute vectors from the sample data
        let vectors = PkPvwVectors::compute(&encryption_data)?;
        let vectors_standard = vectors.standard_form();

        // Extract circuit parameters
        let circuit_params = CircuitParams {
            n: pvw_params.l, // Ring dimension/polynomial degree
            n_parties: pvw_params.n, // Number of parties
            k: pvw_params.k, // LWE dimension
        };

        // Create TOML generator and generate file
        let toml_generator = PkPvwTomlGenerator::new(crypto_params, bounds, vectors_standard, circuit_params);
        toml_generator.generate_toml(output_dir)?;

        println!("✅ Generated pk_pvw.toml");
        Ok(())
    }
}
