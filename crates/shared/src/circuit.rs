//! Circuit trait definition for zkFHE circuit implementations
//!
//! This module defines the core traits and configuration structures that all
//! zkFHE circuit implementations must use. It provides a unified interface
//! for parameter generation, TOML file creation, and configuration validation.
use crate::errors::ZkFheResult;
use fhe::bfv::BfvParameters;
use std::path::Path;
use std::sync::Arc;

/// Circuit trait that all circuit implementations must implement
///
/// This trait defines the contract that every zkFHE circuit implementation
/// must fulfill. It provides methods for parameter generation, TOML file
/// creation, and configuration validation.
pub trait Circuit {
    /// The name of the circuit
    ///
    /// This should be a short, unique identifier for the circuit.
    /// It's used in CLI commands and error messages.
    fn name(&self) -> &'static str;

    /// A description of the circuit
    ///
    /// This should provide a brief description of what the circuit does
    /// and its intended use case.
    fn description(&self) -> &'static str;

    /// Generate parameters for the circuit
    ///
    /// This method should generate all the circuit-specific parameters
    /// needed for the zero-knowledge proof, including bounds, vectors,
    /// and any other circuit-specific data.
    fn generate_params(&self, bfv_params: &Arc<BfvParameters>) -> ZkFheResult<()>;

    /// Generate TOML file for the circuit
    ///
    /// This method should create a TOML file containing all the parameters
    /// needed for the Noir circuit to function correctly.
    fn generate_toml(&self, bfv_params: &Arc<BfvParameters>, output_dir: &Path) -> ZkFheResult<()>;
}
