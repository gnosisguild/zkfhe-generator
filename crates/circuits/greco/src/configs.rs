//! Config file generation for Greco circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

use crate::bounds::{GrecoBounds, GrecoCryptographicParameters};
use crate::template::GrecoTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Greco circuit config files
pub struct GrecoConfigsGenerator;

impl GrecoConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (q_mod_t, moduli, k0is)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, bit widths)
    /// * `parameter_type` - Parameter type (trbfv or bfv) to determine constant names
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &GrecoCryptographicParameters,
        bounds: &GrecoBounds,
        template_params: &GrecoTemplateParams,
        _parameter_type: &str,
    ) -> ZkFheResult<String> {
        // Format QIS array
        let qis_str = crypto_params
            .moduli
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format K0IS array
        let k0is_str = crypto_params
            .k0is
            .iter()
            .map(|k| k.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format PK_BOUNDS array
        let pk_bounds_str = bounds
            .pk_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format R1_LOW_BOUNDS array
        let r1_low_bounds_str = bounds
            .r1_low_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format R1_UP_BOUNDS array
        let r1_up_bounds_str = bounds
            .r1_up_bounds
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

        // Format P1_BOUNDS array
        let p1_bounds_str = bounds
            .p1_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        // Format P2_BOUNDS array
        let p2_bounds_str = bounds
            .p2_bounds
            .iter()
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let configs = format!(
            r#"use crate::core::greco::Configs as GrecoConfigs;

// Global configs for Greco circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
greco (USED FOR ENCRYPTION TRBFV x PVSS)
-------------------------------------
************************************/

// greco - bit parameters
pub global GRECO_BIT_PK: u32 = {};
pub global GRECO_BIT_CT: u32 = {};
pub global GRECO_BIT_U: u32 = {};
pub global GRECO_BIT_E0: u32 = {};
pub global GRECO_BIT_E1: u32 = {};
pub global GRECO_BIT_K: u32 = {};
pub global GRECO_BIT_R1: u32 = {};
pub global GRECO_BIT_R2: u32 = {};
pub global GRECO_BIT_P1: u32 = {};
pub global GRECO_BIT_P2: u32 = {};

// greco - bounds
pub global GRECO_Q_MOD_T: Field = {};
pub global GRECO_K0IS: [Field; L] = [{}];
pub global GRECO_PK_BOUNDS: [Field; L] = [{}];
pub global GRECO_E0_BOUND: Field = {};
pub global GRECO_E1_BOUND: Field = {};
pub global GRECO_U_BOUND: Field = {};
pub global GRECO_K1_LOW_BOUND: Field = {};
pub global GRECO_K1_UP_BOUND: Field = {};
pub global GRECO_R1_LOW_BOUNDS: [Field; L] = [{}];
pub global GRECO_R1_UP_BOUNDS: [Field; L] = [{}];
pub global GRECO_R2_BOUNDS: [Field; L] = [{}];
pub global GRECO_P1_BOUNDS: [Field; L] = [{}];
pub global GRECO_P2_BOUNDS: [Field; L] = [{}];

// greco - configs
pub global GRECO_CONFIGS: GrecoConfigs<N, L> = GrecoConfigs::new(
    GRECO_Q_MOD_T,
    QIS,
    GRECO_K0IS,
    GRECO_PK_BOUNDS,
    GRECO_E0_BOUND,
    GRECO_E1_BOUND,
    GRECO_U_BOUND,
    GRECO_R1_LOW_BOUNDS,
    GRECO_R1_UP_BOUNDS,
    GRECO_R2_BOUNDS,
    GRECO_P1_BOUNDS,
    GRECO_P2_BOUNDS,
    GRECO_K1_LOW_BOUND,
    GRECO_K1_UP_BOUND
);
"#,
            template_params.base.n, // N
            template_params.base.l, // L
            qis_str,                // QIS array
            template_params.bit_pk, // BIT_PK
            template_params.bit_ct, // BIT_CT
            template_params.bit_u,  // BIT_U
            template_params.bit_e0, // BIT_E0
            template_params.bit_e1, // BIT_E1
            template_params.bit_k,  // BIT_K
            template_params.bit_r1, // BIT_R1
            template_params.bit_r2, // BIT_R2
            template_params.bit_p1, // BIT_P1
            template_params.bit_p2, // BIT_P2
            crypto_params.q_mod_t,  // Q_MOD_T
            k0is_str,               // K0IS array
            pk_bounds_str,          // PK_BOUNDS array
            bounds.e0_bound,        // E0_BOUND
            bounds.e1_bound,        // E1_BOUND
            bounds.u_bound,         // U_BOUND
            bounds.k1_low_bound,    // K1_LOW_BOUND
            bounds.k1_up_bound,     // K1_UP_BOUND
            r1_low_bounds_str,      // R1_LOW_BOUNDS array
            r1_up_bounds_str,       // R1_UP_BOUNDS array
            r2_bounds_str,          // R2_BOUNDS array
            p1_bounds_str,          // P1_BOUNDS array
            p2_bounds_str,          // P2_BOUNDS array
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
        crypto_params: &GrecoCryptographicParameters,
        bounds: &GrecoBounds,
        template_params: &GrecoTemplateParams,
        output_dir: &Path,
        filename: &str,
        _parameter_type: &str,
    ) -> ZkFheResult<PathBuf> {
        let content =
            Self::generate_configs(crypto_params, bounds, template_params, _parameter_type)?;
        let output_path = output_dir.join(filename);
        std::fs::write(&output_path, content)?;
        Ok(output_path)
    }
}
