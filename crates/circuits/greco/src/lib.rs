//! Greco circuit parameter generation in Rust
//!
//! This crate provides the Greco circuit parameter generation in Rust.
//! The Greco circuit is a zero-knowledge proof circuit for BFV homomorphic
//! encryption that enables proving correct encryption without revealing
//! the secret key or plaintext.
//!
//! - **Bounds Calculation**: Computes valid ranges for polynomial coefficients
//! - **Vector Generation**: Creates input validation vectors for zero-knowledge proofs
//! - **TOML Generation**: Produces Noir-compatible TOML files
//! - **Configuration Validation**: Ensures cryptographic parameters are secure
pub mod bounds;
pub mod circuit;
pub mod sample;
pub mod toml;
pub mod vectors;
