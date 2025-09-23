//! Shared utilities and traits for zkFHE circuit generation
//!
//! This crate provides common functionality used across all circuit implementations.
//! It defines the core traits, configuration structures, and validation utilities
//! that enable a modular approach to zkFHE circuit parameter generation.
//!
//! - **`bfv`**: BFV (Brakerski-Fan-Vercauteren) homomorphic encryption configuration and helpers
//! - **`circuit`**: Core traits and configuration structures for circuit implementations
//! - **`constants`**: Cryptographic constants used across all circuits
//! - **`toml`**: TOML file generation traits and utilities
//! - **`utils`**: General utility functions for string conversion and serialization
//! - **`validation`**: Parameter validation utilities for ensuring correct configurations

// Core modules
pub mod circuit;
pub mod constants;
pub mod errors;
pub mod toml;
pub mod utils;

// Re-export commonly used items for convenience
pub use circuit::{Circuit, SupportedParameterType};
pub use constants::{ZKP_MODULUS, get_zkp_modulus};
pub use errors::{BfvError, CircuitError, TomlError, ValidationError, ZkFheError, ZkFheResult};
pub use toml::TomlGenerator;
