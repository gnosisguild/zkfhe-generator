//! Circuit trait definition for zkFHE circuit implementations
//!
//! This module defines the core traits and configuration structures that all
//! zkFHE circuit implementations must use. It provides a unified interface
//! for parameter generation, TOML file creation, and configuration validation.
//!
//! ## Parameter Types
//!
//! The `ParameterType` enum supports flexible parameter selection:
//! - **`Trbfv`**: Threshold BFV parameters with stricter security constraints (40-61 bit primes)
//! - **`Bfv`**: Standard BFV parameters with simpler conditions (40-63 bit primes including 62-bit primes)
//!
//! This design allows circuits to support multiple parameter types while maintaining
//! clean separation between parameter generation and circuit logic.
use crate::errors::ZkFheResult;
use fhe::bfv::BfvParameters;
use std::path::Path;
use std::sync::Arc;

/// Supported parameter types for zkFHE circuits
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParameterType {
    /// Threshold BFV parameters with stricter security constraints (40-61 bit primes)
    Trbfv,
    /// Standard BFV parameters with simpler conditions (40-63 bit primes including 62-bit primes)
    Bfv, // we might have more in the future like CKKS.
}

impl ParameterType {
    /// Get the string representation of the parameter type
    pub fn as_str(&self) -> &'static str {
        match self {
            ParameterType::Trbfv => "trbfv",
            ParameterType::Bfv => "bfv",
        }
    }

    /// Parse parameter type from string
    pub fn to_str(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "trbfv" => Ok(ParameterType::Trbfv),
            "bfv" => Ok(ParameterType::Bfv),
            _ => anyhow::bail!("Unknown parameter type: {}. Supported types: trbfv, bfv", s),
        }
    }
}

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

    /// Generate TOML file for the circuit
    ///
    /// This method should create a TOML file containing all the parameters
    /// needed for the Noir circuit to function correctly.
    fn generate_toml(&self, bfv_params: &Arc<BfvParameters>, output_dir: &Path) -> ZkFheResult<()>;
}
