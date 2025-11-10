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
}

impl DecShareTrBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        bounds: &DecShareTrBfvBoundsData,
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
        })
    }
}

/// Generator for Decryption Share TRBFV circuit main.nr templates
pub struct DecShareTrBfvMainTemplate;

impl MainTemplateGenerator<DecShareTrBfvTemplateParams> for DecShareTrBfvMainTemplate {
    fn generate_template(&self, params: &DecShareTrBfvTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use dec_share_trbfv::{DecryptionShareCorrectness, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for Decryption Share TRBFV circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}>,
    c_0: [Polynomial<{}>; {}],
    c_1: [Polynomial<{}>; {}],
    s: [Polynomial<{}>; {}],
    e: [Polynomial<{}>; {}],
    r_1: [Polynomial<{}>; {}],
    r_2: [Polynomial<{}>; {}],
    d: [Polynomial<{}>; {}],
    // TODO: Other parameters...
) {{
    // TODO: Your logic here...

    // Create Decryption Share Correctness circuit instance.
    let dec_share: DecryptionShareCorrectness<{}, {}, {}, {}, {}, {}, {}, {}> = DecryptionShareCorrectness::new(
        params,
        c_0,
        c_1,
        s,
        e,
        r_1,
        r_2,
        d,
    );

    // Verify decryption share correctness
    dec_share.verify_decryption_share_correctness();

    // TODO: Your logic here...
    }}"#,
            import_example,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            2 * params.base.n - 1,
            params.base.l,
            params.base.n - 1,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.bit_ct,
            params.bit_s,
            params.bit_e,
            params.bit_r1,
            params.bit_r2,
            params.bit_d,
        );

        Ok(template)
    }
}
