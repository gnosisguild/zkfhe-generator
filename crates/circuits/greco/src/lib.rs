//! Greco circuit parameter generation in Rust
//!
//! This crate provides the Greco circuit parameter generation in Rust.
//! The Greco circuit is a zero-knowledge proof circuit for BFV homomorphic
//! encryption that enables proving correct encryption without revealing
//! the secret key or plaintext.
pub mod bounds;
pub mod circuit;
pub mod sample;
pub mod toml;
pub mod vectors;
