//! Config file generation for Public Key Aggregation TRBFV circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, Configs) that can be imported in the main circuit.

use crate::bounds::PkAggTrBfvCryptographicParameters;
use crate::template::PkAggTrBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Public Key Aggregation TRBFV circuit config files
pub struct PkAggTrBfvConfigsGenerator;

impl PkAggTrBfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli)
    /// * `template_params` - Template parameters (N, L)
    /// * `parameter_type` - Parameter type (trbfv) to determine constant names
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &PkAggTrBfvCryptographicParameters,
        template_params: &PkAggTrBfvTemplateParams,
        _parameter_type: &str,
    ) -> ZkFheResult<String> {
        // Format QIS array
        let qis_str = crypto_params
            .moduli
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let configs = format!(
            r#"use crate::core::trbfv_pk_agg::Configs as PkAggTrBfvConfigs;

// Global configs for Public Key Aggregation TRBFV circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
pk_agg_trbfv (CIRCUIT 5 - PUBLIC KEY AGGREGATION TRBFV)
-------------------------------------
************************************/

// pk_agg_trbfv - bit parameters
pub global PK_AGG_TRBFV_BIT_PK: u32 = {};

// pk_agg_trbfv - configs
pub global PK_AGG_TRBFV_CONFIGS: PkAggTrBfvConfigs<L> = PkAggTrBfvConfigs::new(
    QIS,
);
"#,
            template_params.base.n, // N
            template_params.base.l, // L
            qis_str,                // QIS array
            template_params.bit_pk, // PK_AGG_TRBFV_BIT_PK
        );

        Ok(configs)
    }

    /// Generate and write the config file to the output directory
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters
    /// * `template_params` - Template parameters
    /// * `output_dir` - Directory where the config file should be written
    /// * `filename` - Name of the config file (e.g., "trbfv.nr")
    /// * `parameter_type` - Parameter type (trbfv) to determine constant names
    ///
    /// # Returns
    ///
    /// Path to the generated config file
    pub fn generate_configs_file(
        crypto_params: &PkAggTrBfvCryptographicParameters,
        template_params: &PkAggTrBfvTemplateParams,
        output_dir: &Path,
        filename: &str,
        parameter_type: &str,
    ) -> ZkFheResult<PathBuf> {
        let content = Self::generate_configs(crypto_params, template_params, parameter_type)?;
        let output_path = output_dir.join(filename);
        std::fs::write(&output_path, content)?;
        Ok(output_path)
    }
}
