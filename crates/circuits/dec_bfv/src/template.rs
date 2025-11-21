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
    /// Bit width for noise bound checking
    pub bit_noise: u32,
}

impl DecBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_honest_parties: usize,
        bounds: &DecBfvBoundsData,
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

        // Noise bound checking uses u_global bit width
        // BIT_NOISE should be based on delta_half, not u_global
        // The noise |u_global - delta * message| must be < delta_half
        let bit_noise = calculate_bit_width(&bounds.delta_half)?;

        Ok(Self {
            base,
            num_honest_parties,
            bit_ct,
            bit_s,
            bit_u,
            bit_r1,
            bit_r2,
            bit_noise,
        })
    }
}

/// Generator for BFV Decryption circuit main.nr templates
pub struct DecBfvMainTemplate;

impl MainTemplateGenerator<DecBfvTemplateParams> for DecBfvMainTemplate {
    fn generate_template(&self, params: &DecBfvTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use dec_bfv::{HonestCiphertextAggregationDecryption, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for BFV Decryption circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}, {}>,
    honest_c0: [[Polynomial<{}>; {}]; {}],
    honest_c1: [[Polynomial<{}>; {}]; {}],
    sum_c0: [Polynomial<{}>; {}],
    sum_c1: [Polynomial<{}>; {}],
    s: [Polynomial<{}>; {}],
    u_i: [Polynomial<{}>; {}],
    r_1: [Polynomial<{}>; {}],
    r_2: [Polynomial<{}>; {}],
    u_global: Polynomial<{}>,
    crt_quotients: [Polynomial<{}>; {}],
    message: Polynomial<{}>,
) {{
    // TODO: Your logic here...

    // Create Honest Ciphertext Aggregation Decryption circuit instance
    let dec_bfv: HonestCiphertextAggregationDecryption<{}, {}, {}, {}, {}, {}, {}, {}, {}> = 
        HonestCiphertextAggregationDecryption::new(
            params,
            honest_c0,
            honest_c1,
            sum_c0,
            sum_c1,
            s,
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            message,
        );

    // Verify correct decryption
    dec_bfv.verify();

    // TODO: Your logic here...
}}"#,
            import_example,
            params.base.n,             // N
            params.num_honest_parties, // H
            params.base.l,             // L
            params.base.n,             // honest_c0 N
            params.base.l,             // honest_c0 L
            params.num_honest_parties, // honest_c0 H
            params.base.n,             // honest_c1 N
            params.base.l,             // honest_c1 L
            params.num_honest_parties, // honest_c1 H
            params.base.n,             // sum_c0 N
            params.base.l,             // sum_c0 L
            params.base.n,             // sum_c1 N
            params.base.l,             // sum_c1 L
            params.base.n,             // s N
            params.base.l,             // s L
            params.base.n,             // u_i N
            params.base.l,             // u_i L
            2 * params.base.n - 1,     // r_1 polynomial degree (2N-1)
            params.base.l,             // r_1 L
            params.base.n - 1,         // r_2 polynomial degree (N-1)
            params.base.l,             // r_2 L
            params.base.n,             // u_global N
            params.base.n,             // crt_quotients N
            params.base.l,             // crt_quotients L
            params.base.n,             // message N
            params.base.n,             // Circuit N
            params.num_honest_parties, // Circuit H
            params.base.l,             // Circuit L
            params.bit_ct,             // Circuit BIT_CT
            params.bit_s,              // Circuit BIT_S
            params.bit_u,              // Circuit BIT_U
            params.bit_r1,             // Circuit BIT_R1
            params.bit_r2,             // Circuit BIT_R2
            params.bit_noise,          // Circuit BIT_NOISE
        );

        Ok(template)
    }
}
