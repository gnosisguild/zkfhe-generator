//! Main template generation for Greco circuit
//!
//! This module contains the main.nr template generation logic specific to the Greco circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Greco circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Greco bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct GrecoBoundsData {
    pub pk_bounds: Vec<String>,
    pub ct_bounds: Vec<String>,
    pub u_bound: String,
    pub e0_bound: String,
    pub e1_bound: String,
    pub k1_low_bound: String,
    pub k1_up_bound: String,
    pub r1_low_bounds: Vec<String>,
    pub r1_up_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
    pub p1_bounds: Vec<String>,
    pub p2_bounds: Vec<String>,
}

/// Greco-specific template parameters
///
/// This structure contains the parameters specific to the Greco circuit,
/// extending the base parameters with Greco-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct GrecoTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for public key bounds
    pub bit_pk: u32,
    /// Bit width for ciphertext bounds
    pub bit_ct: u32,
    /// Bit width for u bounds
    pub bit_u: u32,
    /// Bit width for e0 bounds
    pub bit_e0: u32,
    /// Bit width for e1 bounds
    pub bit_e1: u32,
    /// Bit width for k1 bounds
    pub bit_k: u32,
    /// Bit width for r1 bounds
    pub bit_r1: u32,
    /// Bit width for r2 bounds
    pub bit_r2: u32,
    /// Bit width for p1 bounds
    pub bit_p1: u32,
    /// Bit width for p2 bounds
    pub bit_p2: u32,
}

impl GrecoTemplateParams {
    /// Create Greco template parameters from bounds
    pub fn from_bounds(base: BaseTemplateParams, bounds: &GrecoBoundsData) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_pk = calculate_bit_width(&bounds.pk_bounds[0])?;
        let bit_ct = calculate_bit_width(&bounds.ct_bounds[0])?;
        let bit_u = calculate_bit_width(&bounds.u_bound)?;
        let bit_e0 = calculate_bit_width(&bounds.e0_bound)?;
        let bit_e1 = calculate_bit_width(&bounds.e1_bound)?;

        // For k1, use the maximum of low and up bounds
        let k1_low = calculate_bit_width(&bounds.k1_low_bound)?;
        let k1_up = calculate_bit_width(&bounds.k1_up_bound)?;
        let bit_k = k1_low.max(k1_up);

        // For r1, use the maximum of all low and up bounds
        let mut bit_r1 = 0;
        for bound in bounds
            .r1_low_bounds
            .iter()
            .chain(bounds.r1_up_bounds.iter())
        {
            bit_r1 = bit_r1.max(calculate_bit_width(bound)?);
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
            bit_k,
            bit_r1,
            bit_r2,
            bit_p1,
            bit_p2,
        })
    }
}

/// Generator for Greco circuit main.nr templates
pub struct GrecoMainTemplate;

impl MainTemplateGenerator<GrecoTemplateParams> for GrecoMainTemplate {
    fn generate_template(&self, params: &GrecoTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use greco::{Greco, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for Greco circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}>,
    pk0is: [Polynomial<{}>; {}],
    pk1is: [Polynomial<{}>; {}],
    ct0is: [Polynomial<{}>; {}],
    ct1is: [Polynomial<{}>; {}],
    u: Polynomial<{}>,
    e0: Polynomial<{}>,
    e1: Polynomial<{}>,
    e0is: [Polynomial<{}>; {}],
    k1: Polynomial<{}>,
    r1is: [Polynomial<{}>; {}],
    r2is: [Polynomial<{}>; {}],
    p1is: [Polynomial<{}>; {}],
    p2is: [Polynomial<{}>; {}],
    // TODO: Other parameters...
) {{
    // TODO: Your logic here...

    // Create Greco circuit instance.
    let greco: Greco<{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}> = Greco::new(
        params,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1,
        e0is,
        k1,
        r1is,
        r2is,
        p1is,
        p2is,
    );
    
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
            params.base.n,
            params.base.n,
            params.base.n,
            params.base.n,
            params.base.l,
            params.base.n,
            2 * params.base.n - 1,
            params.base.l,
            params.base.n - 1,
            params.base.l,
            2 * params.base.n - 1,
            params.base.l,
            params.base.n - 1,
            params.base.l,
            params.base.n,
            params.base.l,
            params.bit_pk,
            params.bit_ct,
            params.bit_u,
            params.bit_e0,
            params.bit_e1,
            params.bit_k,
            params.bit_r1,
            params.bit_r2,
            params.bit_p1,
            params.bit_p2,
        );

        Ok(template)
    }
}
