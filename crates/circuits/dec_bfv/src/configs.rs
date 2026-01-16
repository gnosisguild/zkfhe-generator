//! Config file generation for BFV Decryption circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, H, BIT_MSG) that can be imported in the main circuit.

use crate::template::DecBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for BFV Decryption circuit config files
pub struct DecBfvConfigsGenerator;

impl DecBfvConfigsGenerator {
    /// Generate the config .nr file content with both SK and E_SM bit parameters
    ///
    /// # Arguments
    ///
    /// * `template_params` - Template parameters (N, L, H, bit_msg)
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs_with_both_sample_types(
        template_params: &DecBfvTemplateParams,
    ) -> ZkFheResult<String> {
        let configs = format!(
            r#"// Global configs for BFV Decryption circuit
pub global N: u32 = {};
pub global L_TRBFV: u32 = {};

/************************************
-------------------------------------
dec_bfv (CIRCUIT 4a - BFV DECRYPTION SK)
-------------------------------------
************************************/

// dec_bfv - bit parameters
pub global DEC_BFV_BIT_MSG_SK: u32 = {};

/************************************
-------------------------------------
dec_bfv (CIRCUIT 4b - BFV DECRYPTION E_SM)
-------------------------------------
************************************/

// dec_bfv - bit parameters
pub global DEC_BFV_BIT_MSG_E_SM: u32 = {};
"#,
            template_params.base.n,  // N
            template_params.base.l,  // L_TRBFV
            template_params.bit_msg, // DEC_BFV_BIT_MSG_SK
            template_params.bit_msg, // DEC_BFV_BIT_MSG_E_SM (same as SK for now)
        );

        Ok(configs)
    }

    /// Generate and write the config file to the output directory
    ///
    /// # Arguments
    ///
    /// * `template_params` - Template parameters
    /// * `output_dir` - Directory where the config file should be written
    /// * `filename` - Name of the config file (e.g., "bfv.nr")
    ///
    /// # Returns
    ///
    /// Path to the generated config file
    pub fn generate_configs_file(
        template_params: &DecBfvTemplateParams,
        output_dir: &Path,
        filename: &str,
    ) -> ZkFheResult<PathBuf> {
        let content = Self::generate_configs_with_both_sample_types(template_params)?;
        let output_path = output_dir.join(filename);
        std::fs::write(&output_path, content)?;
        Ok(output_path)
    }
}
