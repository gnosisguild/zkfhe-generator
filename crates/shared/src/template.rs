//! Main template generation for zkFHE circuits
//!
//! This module provides the infrastructure for generating template main.nr files
//! for different zkFHE circuit implementations. It follows the same pattern as
//! the TOML generation with shared traits and circuit-specific implementations.

use crate::errors::ZkFheError;
use crate::errors::ZkFheResult;
use num_bigint::BigInt;
use std::path::Path;
use std::str::FromStr;

/// Base template parameters shared across all circuits
///
/// This structure contains only the parameters that are common to all circuits:
/// - N: Ring dimension/polynomial degree
/// - L: Number of moduli
///
/// Circuit-specific parameters should be defined in each circuit's template implementation.
#[derive(Debug, Clone)]
pub struct BaseTemplateParams {
    /// Ring dimension/polynomial degree (N)
    pub n: usize,
    /// Number of moduli (L)
    pub l: usize,
    /// Circuit type identifier
    pub circuit_type: String,
}

/// Trait for generating main.nr templates
///
/// This trait defines the contract for generating template main.nr files
/// for different circuit implementations. Each circuit can provide its own
/// template structure while using the shared infrastructure.
pub trait MainTemplateGenerator<T> {
    /// Generate the main.nr template content
    ///
    /// This method should generate a complete main.nr file template with
    /// the appropriate function signature and parameter types based on the
    /// provided circuit-specific parameters.
    ///
    /// # Arguments
    ///
    /// * `params` - The circuit-specific template parameters
    ///
    /// # Returns
    ///
    /// Returns the complete main.nr template content as a string
    fn generate_template(&self, params: &T) -> ZkFheResult<String>;

    /// Generate and write the main.nr template to the output directory
    ///
    /// This method generates the template content and writes it to a main.nr
    /// file in the specified output directory.
    ///
    /// # Arguments
    ///
    /// * `params` - The circuit-specific template parameters
    /// * `output_dir` - The directory where the main.nr file should be written
    ///
    /// # Returns
    ///
    /// Returns `Ok(())` if the template was generated successfully, or an error otherwise
    fn generate_main_file(&self, params: &T, output_dir: &Path) -> ZkFheResult<()> {
        let content = self.generate_template(params)?;
        let main_nr_path = output_dir.join("main.nr");
        std::fs::write(&main_nr_path, content)?;
        Ok(())
    }
}

/// Helper functions for base template parameters
impl BaseTemplateParams {
    /// Create base template parameters
    pub fn new(n: usize, l: usize, circuit_type: &str) -> Self {
        Self {
            n,
            l,
            circuit_type: circuit_type.to_string(),
        }
    }
}

/// Calculate bit width from a bound string
///
/// The formula is: BIT = ceil(log₂(bound)) + 1
pub fn calculate_bit_width(bound_str: &str) -> ZkFheResult<u32> {
    let bound = BigInt::from_str(bound_str).map_err(|e| ZkFheError::Bfv {
        message: format!("Failed to parse bound '{bound_str}': {e}"),
    })?;

    if bound <= BigInt::from(0) {
        return Ok(1); // Minimum 1 bit
    }

    // Calculate log2 and add 1
    let log2 = bound.bits() as f64;
    let bit_width = (log2.ceil() as u32) + 1;

    Ok(bit_width)
}
