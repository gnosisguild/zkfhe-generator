//! Config file generation for Secret Key Shares verification circuit
//!
//! This module generates a .nr config file with all circuit-specific configs
//! (N, L, QIS, bounds, bit parameters, Configs) that can be imported in the main circuit.

use crate::bounds::VerifySharesTrbfvCryptographicParameters;
use crate::template::VerifySharesTrbfvTemplateParams;
use shared::errors::ZkFheResult;
use std::path::{Path, PathBuf};

/// Generator for Verify Shares TRBFV circuit config files
pub struct VerifySharesTrbfvConfigsGenerator;

impl VerifySharesTrbfvConfigsGenerator {
    /// Generate the config .nr file content with both SK and ESM bit parameters
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli, plaintext modulus)
    /// * `template_params` - Template parameters (N, L, bit widths)
    /// * `bit_secret_sk` - The BIT_SECRET value for secret keys
    /// * `bit_secret_esm` - The BIT_SECRET value for smudging noise
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs_with_both_secret_types(
        crypto_params: &VerifySharesTrbfvCryptographicParameters,
        template_params: &VerifySharesTrbfvTemplateParams,
        bit_secret_sk: u32,
        bit_secret_esm: u32,
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
verify_shares (CIRCUIT 2 - VERIFY SHARES)
-------------------------------------
************************************/

// verify_shares - bit parameters
pub global VERIFY_SHARES_BIT_SECRET_SK: u32 = {};
pub global VERIFY_SHARES_BIT_SECRET_E_SM: u32 = {};
pub global VERIFY_SHARES_BIT_SHARE: u32 = {};

// verify_shares - configs
pub global VERIFY_SHARES_CONFIGS_SK: VerifySharesConfigs<L> =
    VerifySharesConfigs::new(QIS);
pub global VERIFY_SHARES_CONFIGS_E_SM: VerifySharesConfigs<L> =
    VerifySharesConfigs::new(QIS);
"#,
            template_params.base.n,    // N
            template_params.base.l,    // L
            qis_str,                   // QIS array
            bit_secret_sk,             // VERIFY_SHARES_BIT_SECRET_SK
            bit_secret_esm,            // VERIFY_SHARES_BIT_SECRET_E_SM
            template_params.bit_share, // VERIFY_SHARES_BIT_SHARE
        );

        Ok(configs)
    }

    /// Generate the config .nr file content (backwards compatibility)
    ///
    /// # Arguments
    ///
    /// * `crypto_params` - Cryptographic parameters (moduli, plaintext modulus)
    /// * `template_params` - Template parameters (N, L, bit widths)
    ///
    /// # Returns
    ///
    /// The complete config file content as a string
    pub fn generate_configs(
        crypto_params: &VerifySharesTrbfvCryptographicParameters,
        template_params: &VerifySharesTrbfvTemplateParams,
    ) -> ZkFheResult<String> {
        Self::generate_configs_with_both_secret_types(
            crypto_params,
            template_params,
            template_params.bit_secret,
            template_params.bit_secret,
        )
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
        template_params: &VerifySharesTrbfvTemplateParams,
        output_dir: &Path,
        filename: &str,
    ) -> ZkFheResult<PathBuf> {
        let content = Self::generate_configs(crypto_params, template_params)?;
        let output_path = output_dir.join(filename);
        std::fs::write(&output_path, content)?;
        Ok(output_path)
    }
}
