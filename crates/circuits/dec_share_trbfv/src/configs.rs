//! Config file generation for Decryption Share TRBFV circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

use crate::bounds::{DecShareTrBfvBounds, DecShareTrBfvCryptographicParameters};
use crate::template::DecShareTrBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Decryption Share TRBFV circuit config files
pub struct DecShareTrBfvConfigsGenerator;

impl DecShareTrBfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, bit widths)
    /// * `parameter_type` - Parameter type (trbfv) to determine constant names
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &DecShareTrBfvCryptographicParameters,
        bounds: &DecShareTrBfvBounds,
        template_params: &DecShareTrBfvTemplateParams,
        _parameter_type: &str,
    ) -> ZkFheResult<String> {
        // Format QIS array
        let qis_str = crypto_params
            .moduli
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format R1_BOUNDS array
        let r1_bounds_str = bounds
            .r1_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format R2_BOUNDS array
        let r2_bounds_str = bounds
            .r2_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let configs = format!(
            r#"use crate::core::trbfv_dec_share::Configs as DecShareTrBfvConfigs;

// Global configs for Decryption Share TRBFV circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
dec_share_trbfv (CIRCUIT 6 - DECRYPTION SHARE TRBFV)
-------------------------------------
************************************/

// dec_share_trbfv - bit parameters
pub global DEC_SHARES_BIT_CT: u32 = {};
pub global DEC_SHARES_BIT_S: u32 = {};
pub global DEC_SHARES_BIT_E: u32 = {};
pub global DEC_SHARES_BIT_R1: u32 = {};
pub global DEC_SHARES_BIT_R2: u32 = {};
pub global DEC_SHARES_BIT_D: u32 = {};

// dec_share_trbfv - bounds
pub global DEC_SHARES_DECRYPTION_SHARE_BOUND: Field = {};
pub global DEC_SHARES_R1_BOUNDS: [Field; L] = [{}];
pub global DEC_SHARES_R2_BOUNDS: [Field; L] = [{}];

// dec_share_trbfv - configs
pub global DEC_SHARES_CONFIGS: DecShareTrBfvConfigs<L> = DecShareTrBfvConfigs::new(
    QIS,
    DEC_SHARES_DECRYPTION_SHARE_BOUND,
    DEC_SHARES_R1_BOUNDS,
    DEC_SHARES_R2_BOUNDS,
);
"#,
            template_params.base.n,        // N
            template_params.base.l,        // L
            qis_str,                       // QIS array
            template_params.bit_ct,        // BIT_CT
            template_params.bit_s,         // BIT_S
            template_params.bit_e,         // BIT_E
            template_params.bit_r1,        // BIT_R1
            template_params.bit_r2,        // BIT_R2
            template_params.bit_d,         // BIT_D
            bounds.decryption_share_bound, // DECRYPTION_SHARE_BOUND
            r1_bounds_str,                 // R1_BOUNDS array
            r2_bounds_str,                 // R2_BOUNDS array
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
    /// * `filename` - Name of the config file (e.g., "trbfv.nr")
    /// * `parameter_type` - Parameter type (trbfv) to determine constant names
    ///
    /// # Returns
    ///
    /// Path to the generated config file
    pub fn generate_configs_file(
        crypto_params: &DecShareTrBfvCryptographicParameters,
        bounds: &DecShareTrBfvBounds,
        template_params: &DecShareTrBfvTemplateParams,
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
