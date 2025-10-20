//! Main template generation for zkFHE circuits
//!
//! This module provides the infrastructure for generating template main.nr files
//! for different zkFHE circuit implementations. It follows the same pattern as
//! the TOML generation with shared traits and circuit-specific implementations.

use crate::errors::ZkFheResult;
use std::path::Path;

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
