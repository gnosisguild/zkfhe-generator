//! Config file generation for Decryption Share Aggregation TRBFV circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

use crate::bounds::DecShareAggTrBfvCryptographicParameters;
use crate::template::DecShareAggTrBfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Decryption Share Aggregation TRBFV circuit config files
pub struct DecShareAggTrBfvConfigsGenerator;

impl DecShareAggTrBfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli, plaintext_modulus, q_inverse_mod_t)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, bit widths)
    /// * `parameter_type` - Parameter type (trbfv) to determine constant names
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &DecShareAggTrBfvCryptographicParameters,
        template_params: &DecShareAggTrBfvTemplateParams,
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
            r#"use crate::core::trbfv_dec_shares_agg::Configs as DecShareAggTrBfvConfigs;

// Global configs for Decryption Share Aggregation TRBFV circuit
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];
pub global PLAINTEXT_MODULUS: Field = {};
pub global Q_INVERSE_MOD_T: Field = {};

/************************************
-------------------------------------
dec_share_agg_trbfv (CIRCUIT 8 - DECRYPTION SHARE AGGREGATION TRBFV)
-------------------------------------
************************************/

// dec_share_agg_trbfv - bit parameters
pub global DEC_SHARES_AGG_BIT_NOISE: u32 = {};

// dec_share_agg_trbfv - configs
pub global DEC_SHARES_AGG_CONFIGS: DecShareAggTrBfvConfigs<L> = DecShareAggTrBfvConfigs::new(
    QIS,
    PLAINTEXT_MODULUS,
    Q_INVERSE_MOD_T,
);
"#,
            template_params.base.l,          // L
            qis_str,                         // QIS array
            crypto_params.plaintext_modulus, // PLAINTEXT_MODULUS
            crypto_params.q_inverse_mod_t,   // Q_INVERSE_MOD_T
            template_params.bit_noise,       // BIT_NOISE
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
        crypto_params: &DecShareAggTrBfvCryptographicParameters,
        template_params: &DecShareAggTrBfvTemplateParams,
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
