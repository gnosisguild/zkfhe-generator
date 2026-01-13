//! Main template generation for Decryption Share Aggregation TRBFV circuit
//!
//! This module contains the main.nr template generation logic specific to the Decryption Share Aggregation TRBFV circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Decryption Share Aggregation TRBFV circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Decryption Share Aggregation TRBFV bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct DecShareAggTrBfvBoundsData {
    pub delta: String,
    pub delta_half: String,
}

/// Decryption Share Aggregation TRBFV-specific template parameters
///
/// This structure contains the parameters specific to the Decryption Share Aggregation TRBFV circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct DecShareAggTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Threshold value T
    pub threshold: u32,
    /// Bit width for noise bounds
    pub bit_noise: u32,
    /// Parameter set (trbfv)
    pub parameter_set: String,
    /// Security level (production or insecure)
    pub security_level: String,
    /// Number of parties
    pub num_parties: u32,
}

impl DecShareAggTrBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        threshold: u32,
        bounds: &DecShareAggTrBfvBoundsData,
        parameter_set: String,
        security_level: String,
        num_parties: u32,
    ) -> ZkFheResult<Self> {
        // Calculate bit width for noise bound
        let bit_noise = calculate_bit_width(&bounds.delta_half)?;

        Ok(Self {
            base,
            threshold,
            bit_noise,
            parameter_set,
            security_level,
            num_parties,
        })
    }
}

/// Generator for Decryption Share Aggregation TRBFV circuit main.nr templates
pub struct DecShareAggTrBfvMainTemplate;

impl MainTemplateGenerator<DecShareAggTrBfvTemplateParams> for DecShareAggTrBfvMainTemplate {
    fn generate_template(&self, params: &DecShareAggTrBfvTemplateParams) -> ZkFheResult<String> {
        // Determine which verification function to use based on security level
        let verify_call = if params.security_level == "production" {
            "dec_share_agg.verify()"
        } else {
            "dec_share_agg.verify_no_bn()"
        };

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    DEC_SHARES_AGG_BIT_NOISE, DEC_SHARES_AGG_CONFIGS, L,
}};
use lib::core::trbfv_dec_shares_agg::DecryptionSharesAggregation;
use lib::math::polynomial::Polynomial;

/// Max number of non-zero coefficients in the message polynomial.
pub global MAX_MSG_NON_ZERO_COEFFS: u32 = {};
/// Threshold.
pub global T: u32 = {};

fn main(
    decryption_shares: [[Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L]; T + 1],
    party_ids: [Field; T + 1],
    message: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    u_global: Polynomial<MAX_MSG_NON_ZERO_COEFFS>,
    crt_quotients: [Polynomial<MAX_MSG_NON_ZERO_COEFFS>; L],
) {{
    let dec_share_agg: DecryptionSharesAggregation<MAX_MSG_NON_ZERO_COEFFS, L, T, DEC_SHARES_AGG_BIT_NOISE> = DecryptionSharesAggregation::new(
        DEC_SHARES_AGG_CONFIGS,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    {};
}}"#,
            params.security_level,
            params.parameter_set,
            params.base.n, // MAX_MSG_NON_ZERO_COEFFS (trimmed degree)
            params.threshold,
            verify_call,
        );

        Ok(template)
    }
}
