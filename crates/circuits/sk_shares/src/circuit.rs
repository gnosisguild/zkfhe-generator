//! This module implements the `Circuit` trait for the Secret-Key Shares
//! circuit. It wires together:
//! - parameter/bounds derivation,
//! - witness vector generation,
//! - and TOML serialization consumed by the prover.

use crate::bounds::SkSharesBounds;
use crate::toml::{CircuitParams, SkSharesTomlGenerator};
use crate::vectors::SkSharesVectors;
use fhe::bfv::BfvParameters;
use rand::thread_rng;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

shared::circuit_struct!(SkSharesCircuit);

impl Circuit for SkSharesCircuit {
    /// Stable identifier of this circuit.
    fn name(&self) -> &'static str {
        "sk_shares"
    }

    /// Description of the circuit.
    fn description(&self) -> &'static str {
        "SK Shares circuit for zero-knowledge FHE proofs using Shamir secret sharing"
    }

    /// Get the parameter type this circuit is configured with
    fn parameter_type(&self) -> ParameterType {
        self.parameter_type
    }

    /// Produces the `sk_shares.toml` artifact for the prover.
    ///
    /// Steps:
    /// 1. Use BFV parameters directly.
    /// 2. Derive cryptographic parameters and scalar bounds.
    /// 3. Build witness vectors from BFV parameters and ciphernode config.
    /// 4. Convert vectors to the canonical standard form.
    /// 5. Assemble circuit sizing parameters.
    /// 6. Serialize everything into TOML at `output_dir`.
    ///
    /// # Errors
    /// - Propagates errors from bounds computation, vector generation, or TOML I/O.
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Use provided config or defaults
        let config = ciphernodes_config
            .cloned()
            .unwrap_or_else(CiphernodesConfig::defaults);

        let selected_params = if self.parameter_type == ParameterType::Trbfv {
            trbfv_params
        } else {
            bfv_params
        };

        // Compute bounds and cryptographic parameters
        let (crypto_params, bounds) = SkSharesBounds::compute(selected_params)?;

        // Generate witness vectors
        let vectors = SkSharesVectors::compute(
            bfv_params.degree(),
            bfv_params.ctx_at_level(0)?.moduli(),
            config.num_parties,
            config.threshold,
            thread_rng(),
        )?;
        let vectors_standard = vectors.standard_form();

        // Circuit parameters for TOML
        let circuit_params = CircuitParams {
            n: bfv_params.ctx_at_level(0)?.moduli().len(),
            n_parties: config.num_parties,
            t: config.threshold,
        };

        // Generate TOML file
        let toml_generator =
            SkSharesTomlGenerator::new(crypto_params, bounds, vectors_standard, circuit_params);
        toml_generator.generate_toml(output_dir)?;

        println!("✅ Generated sk_shares.toml");
        Ok(())
    }
}
