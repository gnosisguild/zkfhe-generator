//! Config file generation for Public Key TRBFV/BFV circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

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
    /// * `parameter_type` - Parameter type (trbfv or bfv) to determine constant names
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &PkBfvCryptographicParameters,
        bounds: &PkBfvBounds,
        template_params: &PkBfvTemplateParams,
        parameter_type: &str,
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

        // Determine constant prefix based on parameter type
        let prefix = if parameter_type == "trbfv" {
            "PK_TRBFV"
        } else {
            "PK_BFV"
        };

        let configs = format!(
            r#"use crate::core::bfv_pk::Configs as BfvPkConfigs;

// Global configs for Public Key {} circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
pk_{} (CIRCUIT {} - PUBLIC KEY {})
-------------------------------------
************************************/

// pk_{} - bit parameters
pub global {}_BIT_EEK: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_R1: u32 = {};
pub global {}_BIT_R2: u32 = {};

// pk_{} - bounds
pub global {}_EEK_BOUND: Field = {};
pub global {}_SK_BOUND: Field = {};
pub global {}_R1_BOUNDS: [Field; L] = [{}];
pub global {}_R2_BOUNDS: [Field; L] = [{}];

// pk_{} - configs
pub global {}_CONFIGS: BfvPkConfigs<N, L> = BfvPkConfigs::new(
    QIS,
    {}_EEK_BOUND,
    {}_SK_BOUND,
    {}_R1_BOUNDS,
    {}_R2_BOUNDS,
);
"#,
            parameter_type.to_uppercase(),
            template_params.base.n,                            // N
            template_params.base.l,                            // L
            qis_str,                                           // QIS array
            parameter_type,                                    // pk_trbfv or pk_bfv
            if parameter_type == "trbfv" { "1" } else { "2" }, // Circuit number
            if parameter_type == "trbfv" {
                "THRESHOLD BFV"
            } else {
                "BFV"
            }, // Circuit description
            parameter_type,                                    // pk_trbfv or pk_bfv
            prefix,                                            // PK_TRBFV or PK_BFV
            template_params.bit_eek,                           // BIT_EEK
            prefix,                                            // PK_TRBFV or PK_BFV
            template_params.bit_sk,                            // BIT_SK
            prefix,                                            // PK_TRBFV or PK_BFV
            template_params.bit_r1,                            // BIT_R1
            prefix,                                            // PK_TRBFV or PK_BFV
            template_params.bit_r2,                            // BIT_R2
            parameter_type,                                    // pk_trbfv or pk_bfv
            prefix,                                            // PK_TRBFV or PK_BFV
            bounds.eek_bound,                                  // EEK_BOUND
            prefix,                                            // PK_TRBFV or PK_BFV
            bounds.sk_bound,                                   // SK_BOUND
            prefix,                                            // PK_TRBFV or PK_BFV
            r1_bounds_str,                                     // R1_BOUNDS array
            prefix,                                            // PK_TRBFV or PK_BFV
            r2_bounds_str,                                     // R2_BOUNDS array
            parameter_type,                                    // pk_trbfv or pk_bfv
            prefix,                                            // PK_TRBFV or PK_BFV
            prefix,                                            // PK_TRBFV or PK_BFV
            prefix,                                            // PK_TRBFV or PK_BFV
            prefix,                                            // PK_TRBFV or PK_BFV
            prefix,                                            // PK_TRBFV or PK_BFV
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
    /// * `filename` - Name of the config file (e.g., "trbfv.nr" or "bfv.nr")
    /// * `parameter_type` - Parameter type (trbfv or bfv) to determine constant names
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
