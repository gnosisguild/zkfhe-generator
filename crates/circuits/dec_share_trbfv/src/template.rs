//! Main template generation for Decryption Share TRBFV circuit
//!
//! This module contains the main.nr template generation logic specific to the Decryption Share TRBFV circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Decryption Share TRBFV circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Decryption Share TRBFV bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct DecShareTrBfvBoundsData {
    pub decryption_share_bound: String,
    pub r1_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
}

/// Decryption Share TRBFV-specific template parameters
///
/// This structure contains the parameters specific to the Decryption Share TRBFV circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct DecShareTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for ciphertext bounds
    pub bit_ct: u32,
    /// Bit width for shares bounds
    pub bit_s: u32,
    /// Bit width for noise bounds
    pub bit_e: u32,
    /// Bit width for r1 bounds
    pub bit_r1: u32,
    /// Bit width for r2 bounds
    pub bit_r2: u32,
    /// Bit width for decryption share bounds
    pub bit_d: u32,
    /// Parameter set (trbfv)
    pub parameter_set: String,
    /// Security level (production or insecure)
    pub security_level: String,
    /// Number of parties
    pub num_parties: u32,
    /// Threshold
    pub threshold: u32,
}

impl DecShareTrBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        bounds: &DecShareTrBfvBoundsData,
        parameter_set: String,
        security_level: String,
        num_parties: u32,
        threshold: u32,
    ) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_d = calculate_bit_width(&bounds.decryption_share_bound)?;

        // For r1, use the maximum of all low and up bounds
        let mut bit_r1 = 0;
        for bound in bounds.r1_bounds.iter() {
            bit_r1 = bit_r1.max(calculate_bit_width(bound)?);
        }

        // For r2, use the maximum of all bounds
        let mut bit_r2 = 0;
        for bound in &bounds.r2_bounds {
            bit_r2 = bit_r2.max(calculate_bit_width(bound)?);
        }

        Ok(Self {
            base,
            bit_ct: bit_r2,
            bit_s: bit_r2,
            bit_e: bit_r2,
            bit_r1,
            bit_r2,
            bit_d,
            parameter_set,
            security_level,
            num_parties,
            threshold,
        })
    }
}

/// Generator for Decryption Share TRBFV circuit main.nr templates
pub struct DecShareTrBfvMainTemplate;

impl MainTemplateGenerator<DecShareTrBfvTemplateParams> for DecShareTrBfvMainTemplate {
    fn generate_template(&self, params: &DecShareTrBfvTemplateParams) -> ZkFheResult<String> {
        let template = format!(
            r#"use lib::configs::{}::{}::{{
    N, L, DEC_SHARES_BIT_CT, DEC_SHARES_BIT_S, DEC_SHARES_BIT_E,
    DEC_SHARES_BIT_R1, DEC_SHARES_BIT_R2, DEC_SHARES_BIT_D,
    DEC_SHARES_CONFIGS,
}};
use lib::core::trbfv_dec_share::DecryptionShare;
use lib::math::polynomial::Polynomial;

/// Number of parties.
pub global N_PARTIES: u32 = {};
/// Threshold.
pub global T: u32 = {};

fn main(
    expected_s_commitment: pub Field,
    expected_e_commitment: pub Field,
    c_0: pub [Polynomial<N>; L],
    c_1: pub [Polynomial<N>; L],
    s: [Polynomial<N>; L],
    e: [Polynomial<N>; L],
    r_1: [Polynomial<(2 * N) - 1>; L],
    r_2: [Polynomial<N - 1>; L],
    d: pub [Polynomial<N>; L],
) {{
    let dec_share: DecryptionShare<N, L, DEC_SHARES_BIT_CT, DEC_SHARES_BIT_S, DEC_SHARES_BIT_E, DEC_SHARES_BIT_R1, DEC_SHARES_BIT_R2, DEC_SHARES_BIT_D> = DecryptionShare::new(
        DEC_SHARES_CONFIGS,
        expected_s_commitment,
        expected_e_commitment,
        c_0,
        c_1,
        s,
        e,
        r_1,
        r_2,
        d,
    );

    dec_share.verify()
}}"#,
            params.security_level, params.parameter_set, params.num_parties, params.threshold,
        );

        Ok(template)
    }
}
