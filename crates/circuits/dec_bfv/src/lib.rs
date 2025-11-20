//! BFV Decryption circuit parameter generation in Rust
//!
//! This crate provides the BFV decryption circuit parameter generation in Rust.
//! The dec_bfv circuit is a zero-knowledge proof circuit for BFV homomorphic
//! decryption that enables proving correct decryption of encrypted Shamir shares
//! without revealing the secret key.
pub mod bounds;
pub mod circuit;
pub mod sample;
pub mod template;
pub mod toml;
pub mod vectors;