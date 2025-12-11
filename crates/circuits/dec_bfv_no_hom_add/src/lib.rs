//! BFV Decryption circuit (no homomorphic addition) parameter generation in Rust
//!
//! This crate provides the BFV decryption circuit parameter generation for insecure parameters.
//! The dec_bfv_no_hom_add circuit is a zero-knowledge proof circuit for BFV homomorphic
//! decryption that enables proving correct decryption of encrypted TRBFV secret key shares
//! without revealing the BFV secret key.
//!
//! Key differences from dec_bfv:
//! - No homomorphic addition step (each ciphertext is decrypted individually)
//! - H honest parties * L TRBFV bases * L' BFV bases = H*L*L' ciphertexts
//! - Single BFV secret key polynomial (not L copies)
//! - TRBFV share aggregation at the end (sum of decrypted shares mod TRBFV moduli)
pub mod bounds;
pub mod circuit;
pub mod sample;
pub mod template;
pub mod toml;
pub mod vectors;
