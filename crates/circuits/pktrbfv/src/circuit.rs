use crate::bounds::PkTrBfvBounds;
use crate::sample::generate_sample_encryption;
use crate::toml::CircuitParams;
use crate::toml::PkTrBfvTomlGenerator;
use crate::vectors::PkTrBfvVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

pub struct PkTrBfvCircuit;

impl Circuit for PkTrBfvCircuit {
    fn name(&self) -> &'static str {
        "pktrbfv"
    }

    fn description(&self) -> &'static str {
        "PkTrBfv zero-knowledge proof circuit for BFV homomorphic public key"
    }

    fn generate_toml(
        &self,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate bounds and vectors directly
        let (crypto_params, bounds) = PkTrBfvBounds::compute(bfv_params, 0)?;
        let encryption_data = generate_sample_encryption(bfv_params).map_err(|e| {
            shared::errors::ZkFheError::Bfv {
                message: e.to_string(),
            }
        })?;

        let vectors: PkTrBfvVectors = PkTrBfvVectors::compute(
            &encryption_data.a,
            &encryption_data.e_rns,
            &encryption_data.sk_rns,
            &encryption_data.public_key,
            bfv_params,
        )?;

        let vectors_standard = vectors.standard_form();

        let circuit_params = CircuitParams {
            n: bfv_params.degree(),
            l: bfv_params.moduli().len(),
        };

        // Create TOML generator and generate file
        let toml_generator =
            PkTrBfvTomlGenerator::new(crypto_params, bounds, vectors_standard, circuit_params);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}
