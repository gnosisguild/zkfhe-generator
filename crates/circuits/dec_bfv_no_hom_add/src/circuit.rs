//! BFV Decryption circuit (no homomorphic addition) implementation
//!
//! This module provides the circuit interface for the dec_bfv_no_hom_add circuit,
//! which proves correct BFV decryption of encrypted TRBFV secret key shares
//! without homomorphic addition.

use crate::bounds::DecBfvNoHomAddBounds;
use crate::sample::generate_sample_decryption_no_hom_add;
use crate::toml::DecBfvNoHomAddTomlGenerator;
use crate::vectors::DecBfvNoHomAddVectors;
use fhe::bfv::BfvParameters;
use shared::Circuit;
use shared::circuit::{CiphernodesConfig, ParameterType};
use shared::toml::TomlGenerator;
use std::path::Path;
use std::sync::Arc;

/// BFV Decryption circuit (no homomorphic addition) implementation
///
/// This circuit proves correct decryption of BFV ciphertexts containing
/// encrypted TRBFV secret key shares. It verifies:
/// 1. BFV decryption of H*L ciphertexts (H honest parties * L TRBFV bases)
/// 2. Each ciphertext decrypts using L' BFV RNS bases
/// 3. CRT reconstruction for each ciphertext to u_global
/// 4. Decoding each u_global to decrypted_share
/// 5. For each TRBFV basis l: sum_h decrypted_shares[h][l] mod trbfv_qi[l] = expected_share[l]
pub struct DecBfvNoHomAddCircuit {
    /// The parameter type (always BFV for this circuit)
    pub parameter_type: ParameterType,
}

impl DecBfvNoHomAddCircuit {
    /// Create a new DecBfvNoHomAddCircuit instance
    pub fn new() -> Self {
        DecBfvNoHomAddCircuit {
            parameter_type: ParameterType::Bfv,
        }
    }
}

impl Default for DecBfvNoHomAddCircuit {
    fn default() -> Self {
        Self::new()
    }
}

impl Circuit for DecBfvNoHomAddCircuit {
    /// Returns the name of the BFV decryption circuit (no homomorphic addition)
    fn name(&self) -> &'static str {
        "dec-bfv-no-hom-add"
    }

    /// Returns a description of the circuit
    fn description(&self) -> &'static str {
        "Zero-knowledge proof circuit for BFV decryption of encrypted TRBFV shares (no homomorphic addition)"
    }

    /// Returns the parameter type this circuit uses
    fn parameter_type(&self) -> ParameterType {
        ParameterType::Bfv // Uses BFV parameters
    }

    /// Generate TOML file with sample data and parameters
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), shared::errors::ZkFheError> {
        // Generate bounds and cryptographic parameters
        let (crypto_params, bounds) = DecBfvNoHomAddBounds::compute(bfv_params, trbfv_params, 0)?;

        // Generate sample decryption data
        let decryption_data =
            generate_sample_decryption_no_hom_add(bfv_params, trbfv_params, ciphernodes_config)
                .map_err(|e| shared::errors::ZkFheError::Bfv {
                    message: e.to_string(),
                })?;

        // Compute witness vectors from the decryption data
        let vectors = DecBfvNoHomAddVectors::compute(
            &decryption_data.honest_ciphertexts,
            &decryption_data.secret_key,
            bfv_params,
            trbfv_params,
        )?;

        // Verify all circuit constraints in Rust before generating TOML
        // This ensures the generated witness data is valid
        vectors.verify(bfv_params, trbfv_params)?;

        // Convert to standard form (reduce modulo ZKP field)
        let vectors_standard = vectors.standard_form();

        // Create TOML generator and generate file
        let toml_generator =
            DecBfvNoHomAddTomlGenerator::new(crypto_params, bounds, vectors_standard);
        toml_generator.generate_toml(output_dir)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_bfv;
    use tempfile::TempDir;

    #[test]
    fn test_circuit_name_and_description() {
        let circuit = DecBfvNoHomAddCircuit::new();
        assert_eq!(circuit.name(), "dec-bfv-no-hom-add");
        assert!(!circuit.description().is_empty());
        assert_eq!(circuit.parameter_type(), ParameterType::Bfv);
    }

    #[test]
    fn test_toml_generation() {
        let circuit = DecBfvNoHomAddCircuit::new();
        let params = test_parameters_bfv();
        let temp_dir = TempDir::new().unwrap();

        let result = circuit.generate_toml(&params, &params, temp_dir.path(), None);
        assert!(
            result.is_ok(),
            "TOML generation should succeed: {:?}",
            result.err()
        );

        // Verify the file was created
        let toml_path = temp_dir.path().join("Prover.toml");
        assert!(toml_path.exists(), "Prover.toml should be created");

        // Read and verify basic structure
        let content = std::fs::read_to_string(&toml_path).unwrap();
        assert!(content.contains("params"));
        assert!(content.contains("honest_c0"));
        assert!(content.contains("expected_aggregated_shares"));
    }

    #[test]
    fn test_toml_generation_with_custom_config() {
        let circuit = DecBfvNoHomAddCircuit::new();
        let params = test_parameters_bfv();
        let temp_dir = TempDir::new().unwrap();

        let config = CiphernodesConfig::new(5, 5, 2);
        let result = circuit.generate_toml(&params, &params, temp_dir.path(), Some(&config));
        assert!(
            result.is_ok(),
            "TOML generation with custom config should succeed: {:?}",
            result.err()
        );

        // Verify the file was created
        let toml_path = temp_dir.path().join("Prover.toml");
        assert!(toml_path.exists(), "Prover.toml should be created");
    }
}
