//! This module implements the `Circuit` trait for the Secret-Key Shares
//! circuit. It wires together:
//! - parameter/bounds derivation,
//! - witness vector generation,
//! - and TOML serialization consumed by the prover.

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

/// Implements the `Circuit` trait so this circuit can be discovered and run
/// by the surrounding tooling.
pub struct SkSharesCircuit;

impl Circuit for SkSharesCircuit {
    /// Stable identifier of this circuit.
    fn name(&self) -> &'static str {
        "sk_shares"
    }

    /// Description of the circuit.
    fn description(&self) -> &'static str {
        "SK Shares circuit for zero-knowledge FHE proofs"
    }

    /// Declares which parameter families are accepted by this circuit.
    ///
    /// This circuit uses PVW parameters (e.g., for RNS moduli and sharing dims).
    fn supported_parameter_types(&self) -> SupportedParameterType {
        SupportedParameterType::Pvw
    }

    /// Pre-generation hook for circuit parameters.
    ///
    /// For `sk_shares` all parameters are computed on-demand during TOML
    /// generation, so this is a no-op that always succeeds.
    fn generate_params(
        &self,
        _bfv_params: &Arc<BfvParameters>,
        _pvw_params: Option<&Arc<PvwParameters>>,
    ) -> Result<(), shared::errors::ZkFheError> {
        Ok(())
    }

    /// Produces the `sk_shares.toml` artifact for the prover.
    ///
    /// Steps:
    /// 1. Validate PVW parameters are present.
    /// 2. Derive cryptographic parameters and scalar bounds.
    /// 3. Build witness vectors from BFV and PVW parameters.
    /// 4. Convert vectors to the canonical standard form.
    /// 5. Assemble circuit sizing parameters.
    /// 6. Serialize everything into TOML at `output_dir`.
    ///
    /// # Errors
    /// - Returns an error if parameters are missing.
    /// - Propagates errors from bounds computation, vector generation, or TOML I/O.
    fn generate_toml(
        &self,
        bfv_params: &Arc<BfvParameters>,
        pvw_params: Option<&Arc<PvwParameters>>,
        output_dir: &Path,
    ) -> Result<(), shared::errors::ZkFheError> {
        let pvw_params = pvw_params.ok_or_else(|| shared::errors::ZkFheError::Bfv {
            message: "PVW parameters are required for sk_shares circuit".to_string(),
        })?;

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

        println!("✅ Generated sk_shares.toml");
        Ok(())
    }
}
