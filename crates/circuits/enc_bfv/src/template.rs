//! Main template generation for BFV Encryption circuit
//!
//! This module contains the main.nr template generation logic specific to the BFV Encryption circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the BFV Encryption circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// BFV Encryption bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct EncBfvBoundsData {
    pub t: String,
    pub q_mod_t: String,
    pub moduli: Vec<u64>,
    pub k0is: Vec<u64>,
    pub u_bound: String,
    pub e0_bound: String,
    pub e1_bound: String,
    pub msg_bound: String,
    pub pk_bounds: Vec<String>,
    pub r1_low_bounds: Vec<String>,
    pub r1_up_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
    pub p1_bounds: Vec<String>,
    pub p2_bounds: Vec<String>,
}

/// BFV Encryption-specific template parameters
///
/// This structure contains the parameters specific to the BFV Encryption circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct EncBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for public key (BIT_PK)
    pub bit_pk: u32,
    /// Bit width for ciphertext (BIT_CT)
    pub bit_ct: u32,
    /// Bit width for u (BIT_U)
    pub bit_u: u32,
    /// Bit width for e0 (BIT_E0)
    pub bit_e0: u32,
    /// Bit width for e1 (BIT_E1)
    pub bit_e1: u32,
    /// Bit width for message (BIT_MSG)
    pub bit_msg: u32,
    /// Bit width for r1 (BIT_R1)
    pub bit_r1: u32,
    /// Bit width for r2 (BIT_R2)
    pub bit_r2: u32,
    /// Bit width for p1 (BIT_P1)
    pub bit_p1: u32,
    /// Bit width for p2 (BIT_P2)
    pub bit_p2: u32,
    /// Parameter set name (bfv) for import path
    pub parameter_set: String,
    /// Security level (production or insecure) for import path
    /// "production" if lambda >= 80, "insecure" otherwise
    pub security_level: String,
    /// Sample type postfix ("SK" or "E_SM") for config names
    pub sample_type_postfix: String,
}

impl EncBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        bounds: &EncBfvBoundsData,
        parameter_set: String,
        security_level: String,
        sample_type_postfix: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_u = calculate_bit_width(&bounds.u_bound)?;
        let bit_e0 = calculate_bit_width(&bounds.e0_bound)?;
        let bit_e1 = calculate_bit_width(&bounds.e1_bound)?;
        let bit_msg = calculate_bit_width(&bounds.msg_bound)?;

        // For pk, use the maximum of all bounds
        let mut bit_pk = 0;
        for bound in &bounds.pk_bounds {
            bit_pk = bit_pk.max(calculate_bit_width(bound)?);
        }

        // For ct, use the maximum of pk bounds (ciphertext has similar bounds to pk)
        let bit_ct = bit_pk;

        // For r1, use the maximum of all low and up bounds
        let mut bit_r1 = 0;
        for (low, up) in bounds.r1_low_bounds.iter().zip(bounds.r1_up_bounds.iter()) {
            bit_r1 = bit_r1.max(calculate_bit_width(low)?);
            bit_r1 = bit_r1.max(calculate_bit_width(up)?);
        }

        // For r2, use the maximum of all bounds
        let mut bit_r2 = 0;
        for bound in &bounds.r2_bounds {
            bit_r2 = bit_r2.max(calculate_bit_width(bound)?);
        }

        // For p1, use the maximum of all bounds
        let mut bit_p1 = 0;
        for bound in &bounds.p1_bounds {
            bit_p1 = bit_p1.max(calculate_bit_width(bound)?);
        }

        // For p2, use the maximum of all bounds
        let mut bit_p2 = 0;
        for bound in &bounds.p2_bounds {
            bit_p2 = bit_p2.max(calculate_bit_width(bound)?);
        }

        Ok(Self {
            base,
            bit_pk,
            bit_ct,
            bit_u,
            bit_e0,
            bit_e1,
            bit_msg,
            bit_r1,
            bit_r2,
            bit_p1,
            bit_p2,
            parameter_set,
            security_level,
            sample_type_postfix,
        })
    }
}

/// Generator for BFV Encryption circuit main.nr templates
pub struct EncBfvMainTemplate;

impl MainTemplateGenerator<EncBfvTemplateParams> for EncBfvMainTemplate {
    fn generate_template(&self, params: &EncBfvTemplateParams) -> ZkFheResult<String> {
        let configs_name = format!("ENC_BFV_CONFIGS_{}", params.sample_type_postfix);
        let bit_params = "ENC_BFV_BIT_CT, ENC_BFV_BIT_E0, ENC_BFV_BIT_E1, ENC_BFV_BIT_MSG, ENC_BFV_BIT_P1, ENC_BFV_BIT_P2, ENC_BFV_BIT_PK, ENC_BFV_BIT_R1, ENC_BFV_BIT_R2, ENC_BFV_BIT_U".to_string();

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L, N, {}, {},
}};
use lib::core::bfv_enc::EncryptionBfv;
use lib::math::polynomial::Polynomial;

fn main(
    expected_pk_commitment: pub Field,
    expected_message_commitment: pub Field,
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
    ct0is: pub [Polynomial<N>; L],
    ct1is: pub [Polynomial<N>; L],
    u: Polynomial<N>,
    e0: Polynomial<N>,
    e0is: [Polynomial<N>; L],
    e0_quotients: [Polynomial<N>; L],
    e1: Polynomial<N>,
    message: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    p1is: [Polynomial<(2 * N) - 1>; L],
    p2is: [Polynomial<N - 1>; L],
) {{
    let enc_bfv: EncryptionBfv<
        N,
        L,
        ENC_BFV_BIT_PK,
        ENC_BFV_BIT_CT,
        ENC_BFV_BIT_U,
        ENC_BFV_BIT_E0,
        ENC_BFV_BIT_E1,
        ENC_BFV_BIT_MSG,
        ENC_BFV_BIT_R1,
        ENC_BFV_BIT_R2,
        ENC_BFV_BIT_P1,
        ENC_BFV_BIT_P2,
    > = EncryptionBfv::new(
        {},
        expected_pk_commitment,
        expected_message_commitment,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e0is,
        e0_quotients,
        e1,
        message,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    enc_bfv.verify();
}}"#,
            params.security_level,
            params.parameter_set,
            bit_params,
            configs_name,
            configs_name, // Used in EncryptionBfv::new
        );

        Ok(template)
    }
}
