//! Config file generation for Secret Key Shares verification circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

use crate::bounds::{VerifySharesTrbfvBounds, VerifySharesTrbfvCryptographicParameters};
use crate::template::VerifySharesTrbfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Verify Shares TRBFV circuit config files
pub struct VerifySharesTrbfvConfigsGenerator;

impl VerifySharesTrbfvConfigsGenerator {
    /// Generate the config .nr file content
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli, plaintext modulus)
    /// * `bounds` - Bounds for the circuit
    /// * `template_params` - Template parameters (N, L, bit widths)
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &VerifySharesTrbfvCryptographicParameters,
        bounds: &VerifySharesTrbfvBounds,
        template_params: &VerifySharesTrbfvTemplateParams,
    ) -> ZkFheResult<String> {
        // Format QIS array
        let qis_str = crypto_params
            .moduli
            .iter()
            .map(|q| q.to_string())
            .collect::<Vec<_>>()
            .join(", ");

        let configs = format!(
            r#"use crate::core::trbfv_verify_shares::Configs as VerifySharesConfigs;

// Global configs for Secret Key Shares verification circuit
pub global N: u32 = {};
pub global L: u32 = {};
pub global QIS: [Field; L] = [{}];

/************************************
-------------------------------------
verify_shares (CIRCUIT 3 - VERIFY SHARES)
-------------------------------------
************************************/

// verify_shares - bit parameters
pub global VERIFY_SHARES_BIT_SK: u32 = {};
pub global VERIFY_SHARES_BIT_SHARE: u32 = {};

// verify_shares - bounds
pub global VERIFY_SHARES_SK_BOUND: Field = {};

// verify_shares - configs
pub global VERIFY_SHARES_CONFIGS: VerifySharesConfigs<L> =
    VerifySharesConfigs::new(QIS, VERIFY_SHARES_SK_BOUND);
"#,
            template_params.base.n,    // N
            template_params.base.l,    // L
            qis_str,                   // QIS array
            template_params.bit_sk,    // VERIFY_SHARES_BIT_SK
            template_params.bit_share, // VERIFY_SHARES_BIT_SHARE
            bounds.sk_bound,           // VERIFY_SHARES_SK_BOUND
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
    ///
    /// # Returns
    ///
    /// Path to the generated config file
    pub fn generate_configs_file(
        crypto_params: &VerifySharesTrbfvCryptographicParameters,
        bounds: &VerifySharesTrbfvBounds,
        template_params: &VerifySharesTrbfvTemplateParams,
        output_dir: &Path,
        filename: &str,
    ) -> ZkFheResult<PathBuf> {
        let content = Self::generate_configs(crypto_params, bounds, template_params)?;
        let output_path = output_dir.join(filename);
        std::fs::write(&output_path, content)?;
        Ok(output_path)
    }
}
