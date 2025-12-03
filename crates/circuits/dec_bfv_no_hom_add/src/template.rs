//! Main template generation for BFV Decryption circuit (no homomorphic addition)
//!
//! This module contains the main.nr template generation logic specific to the
//! BFV Decryption circuit (no homomorphic addition). It generates a template
//! with the correct parameter types and function signature based on the circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// BFV Decryption (no homomorphic addition) bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct DecBfvNoHomAddBoundsData {
    pub s_bound: String,
    pub u_i_bounds: Vec<String>,
    pub u_global_bound: String,
    pub r1_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
    pub delta: String,
    pub delta_half: String,
}

/// BFV Decryption (no homomorphic addition) specific template parameters
///
/// This structure contains the parameters specific to the circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct DecBfvNoHomAddTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of honest parties (H)
    pub num_honest_parties: usize,
    /// Number of TRBFV bases (L)
    pub num_trbfv_bases: usize,
    /// Number of BFV bases (L')
    pub num_bfv_bases: usize,
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
    /// Bit width for message coefficients
    pub bit_msg: u32,
}

impl DecBfvNoHomAddTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_honest_parties: usize,
        num_trbfv_bases: usize,
        num_bfv_bases: usize,
        bounds: &DecBfvNoHomAddBoundsData,
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

        // Message bit width based on delta_half
        let bit_msg = calculate_bit_width(&bounds.delta_half)?;

        Ok(Self {
            base,
            num_honest_parties,
            num_trbfv_bases,
            num_bfv_bases,
            bit_ct,
            bit_s,
            bit_u,
            bit_r1,
            bit_r2,
            bit_msg,
        })
    }
}

/// Generator for BFV Decryption (no homomorphic addition) circuit main.nr templates
pub struct DecBfvNoHomAddMainTemplate;

impl MainTemplateGenerator<DecBfvNoHomAddTemplateParams> for DecBfvNoHomAddMainTemplate {
    fn generate_template(&self, params: &DecBfvNoHomAddTemplateParams) -> ZkFheResult<String> {
        let import_example =
            "// use dec_bfv_no_hom_add::{HonestCiphertextAggregationDecryptionNoHomAdd, Params};
// use polynomial::Polynomial;";

        // Array dimensions from Noir circuit:
        // honest_c0: [[[Polynomial<N>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
        // u_global: [[Polynomial<N>; L]; H] - 2D: [H][L]
        // expected_aggregated_shares: [Polynomial<N>; L] - 1D: [L]
        let template = format!(
            r#"//! Generated main.nr template for BFV Decryption circuit (no homomorphic addition)
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}, {}, {}>,
    honest_c0: [[[Polynomial<{}>; {}]; {}]; {}],
    honest_c1: [[[Polynomial<{}>; {}]; {}]; {}],
    s: Polynomial<{}>,
    u_i: [[[Polynomial<{}>; {}]; {}]; {}],
    r_1: [[[Polynomial<{}>; {}]; {}]; {}],
    r_2: [[[Polynomial<{}>; {}]; {}]; {}],
    u_global: [[Polynomial<{}>; {}]; {}],
    crt_quotients: [[[Polynomial<{}>; {}]; {}]; {}],
    decrypted_shares: [[Polynomial<{}>; {}]; {}],
    expected_aggregated_shares: [Polynomial<{}>; {}],
) {{
    // TODO: Your logic here...

    // Create circuit instance
    let circuit: HonestCiphertextAggregationDecryptionNoHomAdd<{}, {}, {}, {}, {}, {}, {}, {}, {}, {}> = 
        HonestCiphertextAggregationDecryptionNoHomAdd::new(
            params,
            honest_c0,
            honest_c1,
            s,
            u_i,
            r_1,
            r_2,
            u_global,
            crt_quotients,
            decrypted_shares,
            expected_aggregated_shares,
        );

    // Verify correct decryption and aggregation
    circuit.verify();

    // TODO: Your logic here...
}}"#,
            import_example,
            // Params<N, H, L, L_PRIME>
            params.base.n,
            params.num_honest_parties,
            params.num_trbfv_bases,
            params.num_bfv_bases,
            // honest_c0: [[[Polynomial<N>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
            params.base.n,
            params.num_bfv_bases,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // honest_c1: [[[Polynomial<N>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
            params.base.n,
            params.num_bfv_bases,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // s: Polynomial<N>
            params.base.n,
            // u_i: [[[Polynomial<N>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
            params.base.n,
            params.num_bfv_bases,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // r_1: [[[Polynomial<2N-1>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
            2 * params.base.n - 1,
            params.num_bfv_bases,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // r_2: [[[Polynomial<N-1>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
            params.base.n - 1,
            params.num_bfv_bases,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // u_global: [[Polynomial<N>; L]; H] - 2D: [H][L]
            params.base.n,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // crt_quotients: [[[Polynomial<N>; L_PRIME]; L]; H] - 3D: [H][L][L_PRIME]
            params.base.n,
            params.num_bfv_bases,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // decrypted_shares: [[Polynomial<N>; L]; H] - 2D: [H][L]
            params.base.n,
            params.num_trbfv_bases,
            params.num_honest_parties,
            // expected_aggregated_shares: [Polynomial<N>; L] - 1D: [L]
            params.base.n,
            params.num_trbfv_bases,
            // Circuit generic parameters: N, H, L, L_PRIME, BIT_CT, BIT_S, BIT_U, BIT_R1, BIT_R2, BIT_MSG
            params.base.n,
            params.num_honest_parties,
            params.num_trbfv_bases,
            params.num_bfv_bases,
            params.bit_ct,
            params.bit_s,
            params.bit_u,
            params.bit_r1,
            params.bit_r2,
            params.bit_msg,
        );

        Ok(template)
    }
}
