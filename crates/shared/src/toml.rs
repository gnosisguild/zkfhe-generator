//! Shared TOML generation utilities
//!
//! This module contains shared traits and utilities for TOML generation
//! that can be implemented by each circuit.

use crate::errors::{TomlError, ZkFheResult};
use std::path::{Path, PathBuf};

/// Trait for TOML generation that can be implemented by each circuit
pub trait TomlGenerator {
    /// Convert circuit data to TOML string
    fn to_toml_string(&self) -> ZkFheResult<String>;

    /// Get the filename for the TOML file (defaults to "Prover.toml")
    fn toml_filename(&self) -> &'static str {
        "Prover.toml"
    }

    /// Generate TOML file for the circuit
    fn generate_toml(&self, output_dir: &Path) -> ZkFheResult<PathBuf> {
        use std::fs::File;
        use std::io::Write;

        let output_path = output_dir.join(self.toml_filename());
        let mut file = File::create(&output_path).map_err(|_| TomlError::FileCreation {
            path: output_path.display().to_string(),
        })?;

        // Convert to TOML string
        let toml_string = self.to_toml_string()?;

        // Write to file
        file.write_all(toml_string.as_bytes())
            .map_err(|e| TomlError::FileWrite {
                reason: e.to_string(),
            })?;

        Ok(output_path)
    }
}
