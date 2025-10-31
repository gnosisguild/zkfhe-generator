//! Main template generation for Decryption Share TRBFV circuit
//!
//! This module contains the main.nr template generation logic specific to the Decryption Share TRBFV circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Decryption Share TRBFV circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator};

/// Decryption Share TRBFV bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct DecShareTrBfvBoundsData {
    pub s_bound: String,
    pub e_bound: String,
    pub decryption_share_bound: String,
    pub r1_low_bounds: Vec<String>,
    pub r1_up_bounds: Vec<String>,
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
}

impl DecShareTrBfvTemplateParams {
    pub fn new(base: BaseTemplateParams) -> ZkFheResult<Self> {
        Ok(Self { base })
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
    let dec_share: DecryptionShareCorrectness<{}, {}> = DecryptionShareCorrectness::new(
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
        );

        Ok(template)
    }
}
