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
use crate::constants::DEFAULT_SECURE_LAMBDA;
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

/// Sample type for circuit sample generation
///
/// This enum determines what type of sample input data is generated when creating
/// sample encryption data. It is used by circuits that need to generate
/// different types of threshold shares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SampleType {
    /// Generate a secret key share (sk_sss) share_row
    ///
    /// This is the default sample type that generates shares of a secret key
    /// using secret sharing.
    SecretKey,
    /// Generate a smudging noise share (es_sss) share_row
    ///
    /// This sample type generates shares of smudging noise instead of
    /// secret key shares.
    SmudgingNoise,
}

impl SampleType {
    /// Get the string representation of the sample type
    pub fn as_str(&self) -> &'static str {
        match self {
            SampleType::SecretKey => "secret-key",
            SampleType::SmudgingNoise => "smudging-noise",
        }
    }

    /// Parse sample type from string
    pub fn from_str_to_sample_type(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "secret-key" => Ok(SampleType::SecretKey),
            "smudging-noise" => Ok(SampleType::SmudgingNoise),
            _ => anyhow::bail!(
                "Unknown sample type: {}. Supported types: secret-key, smudging-noise",
                s
            ),
        }
    }
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
    pub fn from_str_to_parameter_type(s: &str) -> anyhow::Result<Self> {
        match s.to_lowercase().as_str() {
            "trbfv" => Ok(ParameterType::Trbfv),
            "bfv" => Ok(ParameterType::Bfv),
            _ => anyhow::bail!("Unknown parameter type: {}. Supported types: trbfv, bfv", s),
        }
    }
}

/// Configuration for cipher node parameters
///
/// This struct holds the number of parties, honest parties, and threshold
/// values used in threshold cryptography circuits. These values can be
/// specified by the user or use defaults for backward compatibility.
#[derive(Debug, Clone)]
pub struct CiphernodesConfig {
    /// Total number of parties (N)
    pub num_parties: usize,
    /// Number of honest parties (H)
    pub num_honest_parties: usize,
    /// Threshold value (T)
    pub threshold: usize,
}

impl CiphernodesConfig {
    /// Create a new CiphernodesConfig with the specified values
    pub fn new(num_parties: usize, num_honest_parties: usize, threshold: usize) -> Self {
        Self {
            num_parties,
            num_honest_parties,
            threshold,
        }
    }

    /// Default values for backward compatibility
    ///
    /// These are the default values used when no configuration is provided:
    /// - num_parties: 3
    /// - num_honest_parties: 3
    /// - threshold: 2
    pub fn defaults() -> Self {
        Self {
            num_parties: 5,
            num_honest_parties: 5,
            threshold: 2,
        }
    }
}

/// Security level classification based on lambda (security parameter)
///
/// Parameters are considered secure if lambda >= 80, and insecure if lambda < 80.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// Secure parameters (lambda >= DEFAULT_SECURE_LAMBDA)
    Secure,
    /// Insecure parameters (lambda < DEFAULT_SECURE_LAMBDA)
    Insecure,
}

impl SecurityLevel {
    /// Determine security level from lambda value
    ///
    /// # Arguments
    ///
    /// * `lambda` - The security parameter (λ)
    ///
    /// # Returns
    ///
    /// Returns `SecurityLevel::Secure` if lambda >= DEFAULT_SECURE_LAMBDA, otherwise `SecurityLevel::Insecure`
    pub fn from_lambda(lambda: usize) -> Self {
        if lambda >= DEFAULT_SECURE_LAMBDA {
            SecurityLevel::Secure
        } else {
            SecurityLevel::Insecure
        }
    }

    /// Check if the security level is secure
    pub fn is_secure(&self) -> bool {
        matches!(self, SecurityLevel::Secure)
    }

    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            SecurityLevel::Secure => "secure",
            SecurityLevel::Insecure => "insecure",
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

    /// Get the security parameter this circuit is configured with
    ///
    /// This method returns the security parameter (λ) that this
    /// circuit instance is configured to use. This allows circuits to
    /// discriminate behavior based on the security parameter.
    ///
    /// The lambda value is explicitly stored in each circuit instance and
    /// can be used for fhe.rs function calls that require the security parameter.
    fn security_parameter(&self) -> usize;

    /// Get the security level of this circuit's parameters
    ///
    /// This method determines whether the parameter set is secure (lambda >= DEFAULT_SECURE_LAMBDA)
    /// or insecure (lambda < DEFAULT_SECURE_LAMBDA) based on the security parameter.
    ///
    /// # Returns
    ///
    /// Returns `SecurityLevel::Secure` if lambda >= DEFAULT_SECURE_LAMBDA, otherwise `SecurityLevel::Insecure`
    fn security_level(&self) -> SecurityLevel {
        SecurityLevel::from_lambda(self.security_parameter())
    }

    /// Get the parameter type this circuit is configured with
    ///
    /// This method returns the parameter type (BFV or trBFV) that this
    /// circuit instance is configured to use. This allows circuits to
    /// discriminate behavior based on the parameter type.
    fn parameter_type(&self) -> ParameterType;

    /// Generate TOML file for the circuit
    ///
    /// This method should create a TOML file containing all the parameters
    /// needed for the Noir circuit to function correctly.
    ///
    /// # Arguments
    ///
    /// * `trbfv_params` - Threshold BFV parameters
    /// * `bfv_params` - Standard BFV parameters
    /// * `output_dir` - Directory where the TOML file should be written
    /// * `ciphernodes_config` - Optional configuration for number of parties, honest parties, and threshold. If None, circuits should use their default values.
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> ZkFheResult<()>;
}

/// Macro to generate a circuit struct with common fields
///
/// This macro generates a struct with `parameter_type` and `security_parameter` (lambda) fields.
/// Circuits can extend this struct by adding additional fields after the macro call.
///
/// # Example
///
/// ```rust,ignore
/// shared::circuit_struct!(MyCircuit);
///
/// impl MyCircuit {
///     pub fn new(parameter_type: ParameterType, lambda: usize) -> Self {
///         Self {
///             parameter_type,
///             security_parameter: lambda,
///         }
///     }
/// }
/// ```
#[macro_export]
macro_rules! circuit_struct {
    ($name:ident) => {
        /// Circuit struct with common configuration fields
        pub struct $name {
            /// The parameter type this circuit is configured with
            pub parameter_type: ParameterType,
            /// The security parameter (λ) this circuit is configured with
            ///
            /// This value is explicitly stored and can be used for fhe.rs function calls
            /// that require the security parameter. Parameters are considered secure
            /// if lambda >= 80, and insecure if lambda < 80.
            pub security_parameter: usize,
        }
    };
}
