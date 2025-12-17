//! Main template generation for Secret Key Shares verification circuit
//!
//! This module contains the main.nr template generation logic specific to the Secret Key Shares circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Secret Key Shares circuit parameters.

use num_bigint::BigUint;
use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Secret Key Shares bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct SkSharesBoundsData {
    pub sk_bound: String,
    pub moduli: Vec<u64>,
}

/// Secret Key Shares-specific template parameters
///
/// This structure contains the parameters specific to the Secret Key Shares circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct SkSharesTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of parties (N_PARTIES)
    pub num_parties: usize,
    /// Threshold value (T)
    pub threshold: usize,
    /// Bit width for secret key (BIT_SK)
    pub bit_sk: u32,
    /// Bit width for shares (BIT_SHARE)
    pub bit_share: u32,
    /// Parameter set name (trbfv or bfv) for import path
    pub parameter_set: String,
}

impl SkSharesTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_parties: usize,
        threshold: usize,
        bounds: &SkSharesBoundsData,
        parameter_set: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit width for secret key bound
        let bit_sk = calculate_bit_width(&bounds.sk_bound)?;

        // Calculate bit width for shares directly from moduli
        // Share bound for each modulus q_j is q_j - 1 (since shares are in [0, q_j))
        let mut bit_share = 0;
        for &q_j in &bounds.moduli {
            let share_bound = BigUint::from(q_j - 1);
            let bit_width = calculate_bit_width(&share_bound.to_string())?;
            bit_share = bit_share.max(bit_width);
        }

        Ok(Self {
            base,
            num_parties,
            threshold,
            bit_sk,
            bit_share,
            parameter_set,
        })
    }
}

/// Generator for Secret Key Shares circuit main.nr templates
pub struct SkSharesMainTemplate;

impl MainTemplateGenerator<SkSharesTemplateParams> for SkSharesMainTemplate {
    fn generate_template(&self, params: &SkSharesTemplateParams) -> ZkFheResult<String> {
        let template = format!(
            r#"use lib::configs::insecure::{}::{{
    L, N, VERIFY_SHARES_BIT_SHARE, VERIFY_SHARES_BIT_SK, VERIFY_SHARES_CONFIGS,
}};
use lib::core::trbfv_verify_shares::VerifyShares;
use lib::math::polynomial::Polynomial;

/// Number of parties.
pub global N_PARTIES: u32 = {};
/// Threshold.
pub global T: u32 = {};

fn main(
    expected_sk_commitment: Field,
    sk: Polynomial<N>,
    y: [[[Field; N_PARTIES + 1]; L]; N],
    h: [[[Field; N_PARTIES + 1]; T + 1]; L],
) -> pub [[Field; L]; N_PARTIES] {{
    let sk_shares: VerifyShares<N, L, N_PARTIES, T, VERIFY_SHARES_BIT_SK, VERIFY_SHARES_BIT_SHARE>
         = VerifyShares::new(VERIFY_SHARES_CONFIGS, expected_sk_commitment, sk, y, h);

    sk_shares.verify()
}}"#,
            params.parameter_set, params.num_parties, params.threshold,
        );

        Ok(template)
    }
}
