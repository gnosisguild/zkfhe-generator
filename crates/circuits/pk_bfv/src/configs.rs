//! Config file generation for Public Key BFV circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, BIT_PK) that can be imported in the main circuit.

use crate::bounds::{PkBfvBounds, PkBfvCryptographicParameters};
use crate::template::PkBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Public Key BFV circuit config files
pub struct PkBfvConfigsGenerator;

impl PkBfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, bit widths)
    /// * `parameter_type` - Parameter type (bfv)
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        _crypto_params: &PkBfvCryptographicParameters,
        _bounds: &PkBfvBounds,
        template_params: &PkBfvTemplateParams,
        _parameter_type: &str,
    ) -> ZkFheResult<String> {
        let prefix = "PK_BFV";

        let configs = format!(
            r#"// Global configs for Public Key BFV circuit
pub global N: u32 = {};
pub global L: u32 = {};

/************************************
-------------------------------------
pk_bfv (CIRCUIT 0 - PUBLIC KEY BFV COMMITMENT)
-------------------------------------
************************************/

// pk_bfv - bit parameters
pub global {}_BIT_PK: u32 = {};
å"#,
            template_params.base.n, // N
            template_params.base.l, // L
            prefix,                 // PK_BFV
            template_params.bit_pk, // BIT_PK
        );

        Ok(configs)
    }

    /// Generate and write the config file to the output directory
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters
    /// * `output_dir` - Directory where the config file should be written
    /// * `filename` - Name of the config file (e.g., "bfv.nr")
    /// * `parameter_type` - Parameter type (bfv)
    ///
    /// # Returns
    ///
    /// Path to the generated config file
    pub fn generate_configs_file(
        crypto_params: &PkBfvCryptographicParameters,
        bounds: &PkBfvBounds,
        template_params: &PkBfvTemplateParams,
        output_dir: &Path,
        filename: &str,
        parameter_type: &str,
    ) -> ZkFheResult<PathBuf> {
        let content =
            Self::generate_configs(crypto_params, bounds, template_params, parameter_type)?;
        let output_path = output_dir.join(filename);
        std::fs::write(&output_path, content)?;
        Ok(output_path)
    }
}
