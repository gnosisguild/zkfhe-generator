//! Main template generation for Greco circuit
//!
//! This module contains the main.nr template generation logic specific to the Greco circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Greco circuit parameters.

use num_bigint::BigInt;
use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator};
use std::str::FromStr;

/// Greco bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct GrecoBoundsData {
    pub pk_bounds: Vec<String>,
    pub ct_bounds: Vec<String>,
    pub u_bound: String,
    pub e_bound: String,
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
    /// Bit width for error bounds
    pub bit_e: u32,
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
    /// Calculate bit width from a bound string
    ///
    /// The formula is: BIT = ceil(log₂(bound)) + 1
    fn calculate_bit_width(bound_str: &str) -> ZkFheResult<u32> {
        let bound = BigInt::from_str(bound_str).map_err(|e| shared::errors::ZkFheError::Bfv {
            message: format!("Failed to parse bound '{bound_str}': {e}"),
        })?;

        if bound <= BigInt::from(0) {
            return Ok(1); // Minimum 1 bit
        }

        // Calculate log2 and add 1
        let log2 = bound.bits() as f64;
        let bit_width = (log2.ceil() as u32) + 1;

        Ok(bit_width)
    }

    /// Create Greco template parameters from bounds
    pub fn from_bounds(base: BaseTemplateParams, bounds: &GrecoBoundsData) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_pk = Self::calculate_bit_width(&bounds.pk_bounds[0])?;
        let bit_ct = Self::calculate_bit_width(&bounds.ct_bounds[0])?;
        let bit_u = Self::calculate_bit_width(&bounds.u_bound)?;
        let bit_e = Self::calculate_bit_width(&bounds.e_bound)?;

        // For k1, use the maximum of low and up bounds
        let k1_low = Self::calculate_bit_width(&bounds.k1_low_bound)?;
        let k1_up = Self::calculate_bit_width(&bounds.k1_up_bound)?;
        let bit_k = k1_low.max(k1_up);

        // For r1, use the maximum of all low and up bounds
        let mut bit_r1 = 0;
        for bound in bounds
            .r1_low_bounds
            .iter()
            .chain(bounds.r1_up_bounds.iter())
        {
            bit_r1 = bit_r1.max(Self::calculate_bit_width(bound)?);
        }

        // For r2, use the maximum of all bounds
        let mut bit_r2 = 0;
        for bound in &bounds.r2_bounds {
            bit_r2 = bit_r2.max(Self::calculate_bit_width(bound)?);
        }

        // For p1, use the maximum of all bounds
        let mut bit_p1 = 0;
        for bound in &bounds.p1_bounds {
            bit_p1 = bit_p1.max(Self::calculate_bit_width(bound)?);
        }

        // For p2, use the maximum of all bounds
        let mut bit_p2 = 0;
        for bound in &bounds.p2_bounds {
            bit_p2 = bit_p2.max(Self::calculate_bit_width(bound)?);
        }

        Ok(Self {
            base,
            bit_pk,
            bit_ct,
            bit_u,
            bit_e,
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
    k1: Polynomial<{}>,
    r1is: [Polynomial<{}>; {}],
    r2is: [Polynomial<{}>; {}],
    p1is: [Polynomial<{}>; {}],
    p2is: [Polynomial<{}>; {}],
    // TODO: Other parameters...
) {{
    // TODO: Your logic here...

    // Create Greco circuit instance.
    let greco: Greco<{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}> = Greco::new(
        params,
        pk0is,
        pk1is,
        ct0is,
        ct1is,
        u,
        e0,
        e1,
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
            params.bit_e,
            params.bit_k,
            params.bit_r1,
            params.bit_r2,
            params.bit_p1,
            params.bit_p2,
        );

        Ok(template)
    }
}
