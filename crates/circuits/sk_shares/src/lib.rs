//! Secret Key Shares verification circuit parameter generation in Rust
//!
//! This crate provides the Secret Key Shares verification circuit parameter generation in Rust.
//! The sk_shares circuit is a zero-knowledge proof circuit for verifying that Shamir secret
//! key shares satisfy the Reed-Solomon parity check.
pub mod bounds;
pub mod circuit;
pub mod sample;
pub mod template;
pub mod toml;
pub mod vectors;
