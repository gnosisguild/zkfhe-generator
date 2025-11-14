//! Main template generation for Decryption Share Aggregation TRBFV circuit
//!
//! This module contains the main.nr template generation logic specific to the Decryption Share Aggregation TRBFV circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Decryption Share Aggregation TRBFV circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Decryption Share Aggregation TRBFV bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct DecShareAggTrBfvBoundsData {
    pub delta: String,
    pub delta_half: String,
}

/// Decryption Share Aggregation TRBFV-specific template parameters
///
/// This structure contains the parameters specific to the Decryption Share Aggregation TRBFV circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct DecShareAggTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Threshold value T
    pub threshold: u32,
    /// Bit width for noise bounds
    pub bit_noise: u32,
}

impl DecShareAggTrBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        threshold: u32,
        bounds: &DecShareAggTrBfvBoundsData,
    ) -> ZkFheResult<Self> {
        // Calculate bit width for noise bound
        let bit_noise = calculate_bit_width(&bounds.delta_half)?;

        Ok(Self {
            base,
            threshold,
            bit_noise,
        })
    }
}

/// Generator for Decryption Share Aggregation TRBFV circuit main.nr templates
pub struct DecShareAggTrBfvMainTemplate;

impl MainTemplateGenerator<DecShareAggTrBfvTemplateParams> for DecShareAggTrBfvMainTemplate {
    fn generate_template(&self, params: &DecShareAggTrBfvTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use dec_share_agg_trbfv::{DecryptionShareAggregation, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for Decryption Share Aggregation TRBFV circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}, {}>,
    decryption_shares: [[Polynomial<{}>; {}]; {}],
    party_ids: [Field; {}],
    message: Polynomial<{}>,
    u_global: Polynomial<{}>,
    crt_quotients: [Polynomial<{}>; {}],
    // TODO: Other parameters...
) {{
    // TODO: Your logic here...

    // Create Decryption Share Aggregation circuit instance.
    let dec_share_agg: DecryptionShareAggregation<{}, {}, {}, {}> = DecryptionShareAggregation::new(
        params,
        decryption_shares,
        party_ids,
        message,
        u_global,
        crt_quotients,
    );

    // Verify decryption share aggregation
    dec_share_agg.verify();

    // TODO: Your logic here...
}}"#,
            import_example,
            params.base.n,
            params.base.l,
            params.threshold,
            params.base.n,
            params.base.l,
            params.threshold + 1,
            params.threshold + 1,
            params.base.n,
            params.base.n,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.threshold,
            params.bit_noise,
        );

        Ok(template)
    }
}
