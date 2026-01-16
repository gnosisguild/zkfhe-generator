//! Main template generation for BFV Decryption circuit
//!
//! This module contains the main.nr template generation logic specific to the BFV Decryption circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the BFV Decryption circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator};

/// BFV Decryption-specific template parameters
///
/// This structure contains the parameters specific to the BFV Decryption circuit,
/// extending the base parameters with circuit-specific bit-widths.
#[derive(Debug, Clone)]
pub struct DecBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of honest parties (H)
    pub num_honest_parties: usize,
    /// Bit width for message
    pub bit_msg: u32,
    /// Parameter set name (bfv) for import path
    pub parameter_set: String,
    /// Security level (production or insecure) for import path
    /// "production" if lambda >= 80, "insecure" otherwise
    pub security_level: String,
    /// Sample type postfix (SK or E_SM)
    pub sample_type_postfix: String,
}

impl DecBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_honest_parties: usize,
        bit_msg: u32,
        parameter_set: String,
        security_level: String,
        sample_type_postfix: String,
    ) -> ZkFheResult<Self> {
        Ok(Self {
            base,
            num_honest_parties,
            bit_msg,
            parameter_set,
            security_level,
            sample_type_postfix,
        })
    }
}

/// Generator for BFV Decryption circuit main.nr templates
pub struct DecBfvMainTemplate;

impl MainTemplateGenerator<DecBfvTemplateParams> for DecBfvMainTemplate {
    fn generate_template(&self, params: &DecBfvTemplateParams) -> ZkFheResult<String> {
        let bit_msg_name = format!("DEC_BFV_BIT_MSG_{}", params.sample_type_postfix);

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L_TRBFV, N, {},
}};
use lib::core::bfv_dec::BfvDecCommitVerify;
use lib::math::polynomial::Polynomial;

/// Number of honest parties.
pub global H: u32 = {};

fn main(
    expected_commitments: [[Field; L_TRBFV]; H],
    decrypted_shares: [[Polynomial<N>; L_TRBFV]; H],
) -> pub Field {{
    let circuit: BfvDecCommitVerify<N, L_TRBFV, H, {}> =
        BfvDecCommitVerify::new(expected_commitments, decrypted_shares);

    circuit.verify()
}}"#,
            params.security_level,
            params.parameter_set,
            bit_msg_name,
            params.num_honest_parties, // H
            bit_msg_name,
        );

        Ok(template)
    }
}
