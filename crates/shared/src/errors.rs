//! Error types for zkFHE circuit generation
//!
//! This module defines specific error types using `thiserror` for better error handling,
//! debugging, and user experience. Each error type provides context about what went wrong
//! and where the error occurred.

use thiserror::Error;

/// Main error type for the zkFHE shared crate
///
/// This enum covers all the different types of errors that can occur
/// during circuit parameter generation and TOML file creation.
#[derive(Error, Debug)]
pub enum ZkFheError {
    /// Validation errors for cryptographic parameters
    #[error("Validation error: {message}")]
    Validation { message: String },

    /// BFV (Brakerski-Fan-Vercauteren) encryption errors
    #[error("BFV encryption error: {message}")]
    Bfv { message: String },

    /// Circuit-specific errors
    #[error("Circuit error: {message}")]
    Circuit { message: String },

    /// TOML generation and file I/O errors
    #[error("TOML generation error: {message}")]
    Toml { message: String },

    /// Mathematical computation errors
    #[error("Mathematical error: {message}")]
    Math { message: String },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config { message: String },

    /// I/O errors for file operations
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// TOML parsing errors
    #[error("TOML parsing error: {0}")]
    TomlParse(#[from] toml::de::Error),

    /// TOML serialization errors
    #[error("TOML serialization error: {0}")]
    TomlSerialize(#[from] toml::ser::Error),

    /// Generic error with context
    #[error("Error: {message}")]
    Generic { message: String },
}

/// Result type alias for zkFHE operations
pub type ZkFheResult<T> = Result<T, ZkFheError>;

/// Validation error type
#[derive(Error, Debug)]
pub enum ValidationError {
    /// Degree validation error
    #[error("Invalid degree: {degree} - {reason}")]
    Degree { degree: usize, reason: String },

    /// Plaintext modulus validation error
    #[error("Invalid plaintext modulus: {modulus} - {reason}")]
    PlaintextModulus { modulus: u64, reason: String },

    /// Ciphertext moduli validation error
    #[error("Invalid ciphertext moduli: {reason}")]
    CiphertextModuli { reason: String },

    /// General validation error
    #[error("Validation failed: {message}")]
    General { message: String },
}

/// BFV encryption error type
#[derive(Error, Debug)]
pub enum BfvError {
    /// Parameter creation error
    #[error("Failed to create BFV parameters: {message}")]
    ParameterCreation { message: String },

    /// Encryption error
    #[error("Encryption failed: {message}")]
    Encryption { message: String },

    /// Decryption error
    #[error("Decryption failed: {message}")]
    Decryption { message: String },

    /// Key generation error
    #[error("Key generation failed: {message}")]
    KeyGeneration { message: String },

    /// Mathematical operation error
    #[error("Mathematical operation failed: {message}")]
    Math { message: String },
}

/// Circuit error type
#[derive(Error, Debug)]
pub enum CircuitError {
    /// Parameter generation error
    #[error("Parameter generation failed: {message}")]
    ParameterGeneration { message: String },

    /// Configuration validation error
    #[error("Configuration validation failed: {message}")]
    ConfigValidation { message: String },

    /// TOML generation error
    #[error("TOML generation failed: {message}")]
    TomlGeneration { message: String },

    /// Circuit-specific computation error
    #[error("Circuit computation failed: {message}")]
    Computation { message: String },
}

/// TOML generation error type
#[derive(Error, Debug)]
pub enum TomlError {
    /// File creation error
    #[error("Failed to create TOML file: {path}")]
    FileCreation { path: String },

    /// File write error
    #[error("Failed to write TOML content: {reason}")]
    FileWrite { reason: String },

    /// Content generation error
    #[error("Failed to generate TOML content: {reason}")]
    ContentGeneration { reason: String },

    /// Serialization error
    #[error("Failed to serialize TOML content: {reason}")]
    Serialization { reason: String },
}

// Conversion implementations for better error handling
impl From<ValidationError> for ZkFheError {
    fn from(err: ValidationError) -> Self {
        ZkFheError::Validation {
            message: err.to_string(),
        }
    }
}

impl From<BfvError> for ZkFheError {
    fn from(err: BfvError) -> Self {
        ZkFheError::Bfv {
            message: err.to_string(),
        }
    }
}

impl From<CircuitError> for ZkFheError {
    fn from(err: CircuitError) -> Self {
        ZkFheError::Circuit {
            message: err.to_string(),
        }
    }
}

impl From<TomlError> for ZkFheError {
    fn from(err: TomlError) -> Self {
        ZkFheError::Toml {
            message: err.to_string(),
        }
    }
}

impl From<String> for ZkFheError {
    fn from(message: String) -> Self {
        ZkFheError::Generic { message }
    }
}

impl From<&str> for ZkFheError {
    fn from(message: &str) -> Self {
        ZkFheError::Generic {
            message: message.to_string(),
        }
    }
}

// Conversion from fhe::Error to ZkfheError
impl From<fhe::Error> for ZkFheError {
    fn from(err: fhe::Error) -> Self {
        ZkFheError::Bfv {
            message: err.to_string(),
        }
    }
}

// Conversion from fhe_math::Error to ZkfheError
impl From<fhe_math::Error> for ZkFheError {
    fn from(err: fhe_math::Error) -> Self {
        ZkFheError::Math {
            message: err.to_string(),
        }
    }
}

// Conversion from Box<dyn std::error::Error> to ZkfheError
impl From<Box<dyn std::error::Error>> for ZkFheError {
    fn from(err: Box<dyn std::error::Error>) -> Self {
        ZkFheError::Generic {
            message: err.to_string(),
        }
    }
}

// Helper functions for creating errors with context
impl ZkFheError {
    /// Create a validation error with a message
    pub fn validation(message: impl Into<String>) -> Self {
        ZkFheError::Validation {
            message: message.into(),
        }
    }

    /// Create a BFV error with a message
    pub fn bfv(message: impl Into<String>) -> Self {
        ZkFheError::Bfv {
            message: message.into(),
        }
    }

    /// Create a circuit error with a message
    pub fn circuit(message: impl Into<String>) -> Self {
        ZkFheError::Circuit {
            message: message.into(),
        }
    }

    /// Create a TOML error with a message
    pub fn toml(message: impl Into<String>) -> Self {
        ZkFheError::Toml {
            message: message.into(),
        }
    }

    /// Create a mathematical error with a message
    pub fn math(message: impl Into<String>) -> Self {
        ZkFheError::Math {
            message: message.into(),
        }
    }

    /// Create a configuration error with a message
    pub fn config(message: impl Into<String>) -> Self {
        ZkFheError::Config {
            message: message.into(),
        }
    }
}
