//! Verify Shares TRBFV circuit parameter generation in Rust
//!
//! This crate provides the Verify Shares TRBFV circuit parameter generation in Rust.
//! The verify-shares-trbfv circuit is a zero-knowledge proof circuit for verifying that Shamir secret
//! key shares satisfy the Reed-Solomon parity check.
pub mod bounds;
pub mod circuit;
pub mod configs;
pub mod sample;
pub mod template;
pub mod toml;
pub mod vectors;
