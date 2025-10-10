use fhe::bfv::BfvParameters;
use pvw::PvwParameters;
use rand::thread_rng;
use shared::toml::TomlGenerator;
use shared::{Circuit, SupportedParameterType};
use std::path::Path;
use std::sync::Arc;

use crate::bounds::SkSharesBounds;
use crate::toml::{CircuitParams, SkSharesTomlGenerator};
use crate::vectors::SkSharesVectors;

pub struct SkSharesCircuit;

impl Circuit for SkSharesCircuit {
    fn name(&self) -> &'static str {
        "sk_shares"
    }

    fn description(&self) -> &'static str {
        "SK Shares circuit for zero-knowledge FHE proofs"
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
        bfv_params: &Arc<BfvParameters>,
        pvw_params: Option<&Arc<PvwParameters>>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        let pvw_params = pvw_params.ok_or_else(|| shared::errors::ZkFheError::Bfv {
            message: "PVW parameters are required for sk_shares circuit".to_string(),
        })?;

        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = SkSharesBounds::compute(pvw_params)?;

        let vectors = SkSharesVectors::compute(
            bfv_params.degree(),
            bfv_params.moduli(),
            pvw_params.n,
            pvw_params.t,
            thread_rng(),
        )?;
        let vectors_standard = vectors.standard_form();

        let circuit_params = CircuitParams {
            n: pvw_params.l,
            n_parties: pvw_params.n,
            t: pvw_params.t,
        };

        let toml_generator =
            SkSharesTomlGenerator::new(crypto_params, bounds, vectors_standard, circuit_params);
        toml_generator.generate_toml(output_dir)?;

        println!("✅ Generated pk_pvw.toml");
        Ok(())
    }
}
