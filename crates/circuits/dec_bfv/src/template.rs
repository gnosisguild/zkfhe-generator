//! Main template generation for BFV Decryption circuit
//!
//! This module contains the main.nr template generation logic specific to the BFV Decryption circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the BFV Decryption circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// BFV Decryption bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct DecBfvBoundsData {
    pub s_bound: String,
    pub u_i_bounds: Vec<String>,
    pub u_global_bound: String,
    pub r1_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
    pub delta: String,
    pub delta_half: String,
}

/// BFV Decryption-specific template parameters
///
/// This structure contains the parameters specific to the BFV Decryption circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct DecBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of honest parties (H)
    pub num_honest_parties: usize,
    /// Bit width for ciphertext coefficients
    pub bit_ct: u32,
    /// Bit width for secret key
    pub bit_s: u32,
    /// Bit width for u polynomials
    pub bit_u: u32,
    /// Bit width for r1 quotients
    pub bit_r1: u32,
    /// Bit width for r2 quotients
    pub bit_r2: u32,
    /// Bit width for message
    pub bit_msg: u32,
    /// Parameter set name (bfv) for import path
    pub parameter_set: String,
    /// Security level (production or insecure) for import path
    /// "production" if lambda >= 80, "insecure" otherwise
    pub security_level: String,
}

impl DecBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_honest_parties: usize,
        bounds: &DecBfvBoundsData,
        parameter_set: String,
        security_level: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_s = calculate_bit_width(&bounds.s_bound)?;
        let bit_u_global = calculate_bit_width(&bounds.u_global_bound)?;

        // For u_i bounds, use the maximum
        let mut bit_u_i = 0;
        for bound in &bounds.u_i_bounds {
            bit_u_i = bit_u_i.max(calculate_bit_width(bound)?);
        }
        let bit_u = bit_u_i.max(bit_u_global);

        // For r1, use the maximum of all bounds
        let mut bit_r1 = 0;
        for bound in &bounds.r1_bounds {
            bit_r1 = bit_r1.max(calculate_bit_width(bound)?);
        }

        // For r2, use the maximum of all bounds
        let mut bit_r2 = 0;
        for bound in &bounds.r2_bounds {
            bit_r2 = bit_r2.max(calculate_bit_width(bound)?);
        }

        // Ciphertext coefficients have same bound as r2 (per-modulus)
        let bit_ct = bit_r2;

        // Message bit width - typically small (plaintext modulus)
        // Use a reasonable default or calculate from message bounds if available
        let bit_msg = calculate_bit_width(&bounds.delta_half)?;

        Ok(Self {
            base,
            num_honest_parties,
            bit_ct,
            bit_s,
            bit_u,
            bit_r1,
            bit_r2,
            bit_msg,
            parameter_set,
            security_level,
        })
    }
}

/// Generator for BFV Decryption circuit main.nr templates
pub struct DecBfvMainTemplate;

impl MainTemplateGenerator<DecBfvTemplateParams> for DecBfvMainTemplate {
    fn generate_template(&self, params: &DecBfvTemplateParams) -> ZkFheResult<String> {
        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L_PRIME, L_TRBFV, N, DEC_BFV_BIT_CT, DEC_BFV_BIT_MSG, DEC_BFV_BIT_R1, DEC_BFV_BIT_R2,
    DEC_BFV_BIT_S, DEC_BFV_BIT_U, DEC_BFV_CONFIGS,
}};
use lib::core::bfv_dec::BfvDec;
use lib::math::polynomial::Polynomial;

/// Number of honest parties.
pub global H: u32 = {};

fn main(
    expected_sk_commitment: Field,
    honest_c0: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    honest_c1: [[[Polynomial<N>; L_PRIME]; L_TRBFV]; H],
    s: Polynomial<N>,
    u_i: [[Polynomial<N>; L_PRIME]; L_TRBFV],
    r_1: [[Polynomial<(2 * N) - 1>; L_PRIME]; L_TRBFV],
    r_2: [[Polynomial<N - 1>; L_PRIME]; L_TRBFV],
    u_global: [Polynomial<N>; L_TRBFV],
    crt_quotients: [[Polynomial<N>; L_PRIME]; L_TRBFV],
    message: [Polynomial<N>; L_TRBFV],
) -> pub Field {{
    let dec_bfv: BfvDec<
        N,
        H,
        L_TRBFV,
        L_PRIME,
        DEC_BFV_BIT_CT,
        DEC_BFV_BIT_S,
        DEC_BFV_BIT_U,
        DEC_BFV_BIT_R1,
        DEC_BFV_BIT_R2,
        DEC_BFV_BIT_MSG,
    > = BfvDec::new(
        DEC_BFV_CONFIGS,
        expected_sk_commitment,
        honest_c0,
        honest_c1,
        s,
        u_i,
        r_1,
        r_2,
        u_global,
        crt_quotients,
        message,
    );

    dec_bfv.verify()
}}"#,
            params.security_level, params.parameter_set, params.num_honest_parties,
        );

        Ok(template)
    }
}
