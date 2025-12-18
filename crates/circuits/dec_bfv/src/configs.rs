//! Config file generation for BFV Decryption circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, L_PRIME, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

use crate::bounds::{DecBfvBounds, DecBfvCryptographicParameters};
use crate::template::DecBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for BFV Decryption circuit config files
pub struct DecBfvConfigsGenerator;

impl DecBfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (bfv_moduli, trbfv_moduli, plaintext_modulus, q_inverse_mod_t)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, L_PRIME, bit widths)
    /// * `parameter_type` - Parameter type (bfv) to determine constant names
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &DecBfvCryptographicParameters,
        bounds: &DecBfvBounds,
        template_params: &DecBfvTemplateParams,
        _parameter_type: &str,
    ) -> ZkFheResult<String> {
        // Format BFV QIS array
        let bfv_qis_str = crypto_params
            .bfv_moduli
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format TRBFV QIS array
        let trbfv_qis_str = crypto_params
            .trbfv_moduli
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format U_I_BOUNDS array (per BFV basis, length L_PRIME)
        let u_i_bounds_str = bounds
            .u_i_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format R1_BOUNDS array (per BFV basis, length L_PRIME)
        let r1_bounds_str = bounds
            .r1_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format R2_BOUNDS array (per BFV basis, length L_PRIME)
        let r2_bounds_str = bounds
            .r2_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let configs = format!(
            r#"use crate::core::bfv_dec::Configs as BfvDecConfigs;

// Global configs for BFV Decryption circuit
pub global N: u32 = {};
pub global L_TRBFV: u32 = {};
pub global L_PRIME: u32 = {};
pub global QIS: [Field; L_PRIME] = [{}];
pub global TRBFV_QIS: [Field; L_TRBFV] = [{}];

/************************************
-------------------------------------
dec_bfv (CIRCUIT {} - BFV DECRYPTION)
-------------------------------------
************************************/

// dec_bfv - bit parameters
pub global DEC_BFV_BIT_CT: u32 = {};
pub global DEC_BFV_BIT_S: u32 = {};
pub global DEC_BFV_BIT_U: u32 = {};
pub global DEC_BFV_BIT_R1: u32 = {};
pub global DEC_BFV_BIT_R2: u32 = {};
pub global DEC_BFV_BIT_MSG: u32 = {};

// dec_bfv - bounds
pub global DEC_BFV_PLAINTEXT_MODULUS: Field = {};
pub global DEC_BFV_Q_INVERSE_MOD_T: Field = {};
pub global DEC_BFV_S_BOUND: Field = {};
pub global DEC_BFV_U_I_BOUNDS: [Field; L_PRIME] = [{}];
pub global DEC_BFV_U_GLOBAL_BOUND: Field = {};
pub global DEC_BFV_R1_BOUNDS: [Field; L_PRIME] = [{}];
pub global DEC_BFV_R2_BOUNDS: [Field; L_PRIME] = [{}];
pub global DEC_BFV_DELTA: Field = {};
pub global DEC_BFV_DELTA_HALF: Field = {};

// dec_bfv - configs
pub global DEC_BFV_CONFIGS: BfvDecConfigs<L_TRBFV, L_PRIME> = BfvDecConfigs::new(
    QIS,
    TRBFV_QIS,
    DEC_BFV_PLAINTEXT_MODULUS,
    DEC_BFV_Q_INVERSE_MOD_T,
    DEC_BFV_S_BOUND,
    DEC_BFV_U_I_BOUNDS,
    DEC_BFV_U_GLOBAL_BOUND,
    DEC_BFV_R1_BOUNDS,
    DEC_BFV_R2_BOUNDS,
    DEC_BFV_DELTA,
    DEC_BFV_DELTA_HALF,
);
"#,
            template_params.base.n,              // N
            template_params.base.l,              // L
            crypto_params.bfv_moduli.len(),      // L_PRIME
            bfv_qis_str,                         // BFV_QIS array
            trbfv_qis_str,                       // TRBFV_QIS array
            "5",                                 // Circuit number
            template_params.bit_ct,              // BIT_CT
            template_params.bit_s,               // BIT_S
            template_params.bit_u,               // BIT_U
            template_params.bit_r1,              // BIT_R1
            template_params.bit_r2,              // BIT_R2
            template_params.bit_msg,             // BIT_MSG
            crypto_params.bfv_plaintext_modulus, // PLAINTEXT_MODULUS
            crypto_params.bfv_q_inverse_mod_t,   // Q_INVERSE_MOD_T
            bounds.s_bound,                      // S_BOUND
            u_i_bounds_str,                      // U_I_BOUNDS array
            bounds.u_global_bound,               // U_GLOBAL_BOUND
            r1_bounds_str,                       // R1_BOUNDS array
            r2_bounds_str,                       // R2_BOUNDS array
            bounds.delta,                        // DELTA
            bounds.delta_half,                   // DELTA_HALF
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
    /// * `parameter_type` - Parameter type (bfv) to determine constant names
    ///
    /// # Returns
    ///
    /// Path to the generated config file
    pub fn generate_configs_file(
        crypto_params: &DecBfvCryptographicParameters,
        bounds: &DecBfvBounds,
        template_params: &DecBfvTemplateParams,
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
