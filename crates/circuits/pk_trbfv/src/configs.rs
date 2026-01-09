//! Config file generation for Public Key TRBFV circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.
//!
//! Note: This circuit now only supports TRBFV parameters (not BFV).

use crate::bounds::{PkTrBfvBounds, PkTrBfvCryptographicParameters};
use crate::template::PkTrBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Public Key BFV circuit config files
pub struct PkTrBfvConfigsGenerator;

impl PkTrBfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, bit widths)
    /// * `_parameter_type` - Parameter type (only trbfv is supported now)
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &PkTrBfvCryptographicParameters,
        bounds: &PkTrBfvBounds,
        template_params: &PkTrBfvTemplateParams,
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

        // Only TRBFV is supported now
        let prefix = "PK_TRBFV";

        let configs = format!(
            r#"use crate::core::trbfv_pk::Configs as TrbfvPkConfigs;

// Global configs for Public Key TRBFV circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
pk_trbfv (CIRCUIT 1 - PUBLIC KEY THRESHOLD BFV)
-------------------------------------
************************************/

// pk_trbfv - bit parameters
pub global {}_BIT_EEK: u32 = {};
pub global {}_BIT_SK: u32 = {};
pub global {}_BIT_E_SM: u32 = {};
pub global {}_BIT_R1: u32 = {};
pub global {}_BIT_R2: u32 = {};
pub global {}_BIT_PK: u32 = {};

// pk_trbfv - bounds
pub global {}_EEK_BOUND: Field = {};
pub global {}_SK_BOUND: Field = {};
pub global {}_E_SM_BOUND: Field = {};
pub global {}_R1_BOUNDS: [Field; L] = [{}];
pub global {}_R2_BOUNDS: [Field; L] = [{}];

// pk_trbfv - configs
pub global {}_CONFIGS: TrbfvPkConfigs<N, L> = TrbfvPkConfigs::new(
    QIS,
    {}_EEK_BOUND,
    {}_SK_BOUND,
    {}_E_SM_BOUND,
    {}_R1_BOUNDS,
    {}_R2_BOUNDS,
);
"#,
            template_params.base.n,   // N
            template_params.base.l,   // L
            qis_str,                  // QIS array
            prefix,                   // PK_TRBFV
            template_params.bit_eek,  // BIT_EEK
            prefix,                   // PK_TRBFV
            template_params.bit_sk,   // BIT_SK
            prefix,                   // PK_TRBFV
            template_params.bit_e_sm, // BIT_E_SM
            prefix,                   // PK_TRBFV
            template_params.bit_r1,   // BIT_R1
            prefix,                   // PK_TRBFV
            template_params.bit_r2,   // BIT_R2
            prefix,                   // PK_TRBFV
            template_params.bit_pk,   // BIT_PK
            prefix,                   // PK_TRBFV
            bounds.eek_bound,         // EEK_BOUND
            prefix,                   // PK_TRBFV
            bounds.sk_bound,          // SK_BOUND
            prefix,                   // PK_TRBFV
            bounds.e_sm_bound,        // E_SM_BOUND
            prefix,                   // PK_TRBFV
            r1_bounds_str,            // R1_BOUNDS array
            prefix,                   // PK_TRBFV
            r2_bounds_str,            // R2_BOUNDS array
            prefix,                   // PK_TRBFV
            prefix,                   // PK_TRBFV
            prefix,                   // PK_TRBFV
            prefix,                   // PK_TRBFV
            prefix,                   // PK_TRBFV
            prefix,                   // PK_TRBFV
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
        crypto_params: &PkTrBfvCryptographicParameters,
        bounds: &PkTrBfvBounds,
        template_params: &PkTrBfvTemplateParams,
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
