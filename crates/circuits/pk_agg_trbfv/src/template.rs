use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator};

#[derive(Debug, Clone)]
pub struct PkAggTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of honest parties (H)
    pub num_honest_parties: usize,
}

impl PkAggTrBfvTemplateParams {
    pub fn new(base: BaseTemplateParams, num_honest_parties: usize) -> Self {
        Self {
            base,
            num_honest_parties,
        }
    }
}

/// Generator for TrBFV Public Key Aggregation circuit main.nr templates
pub struct PkAggTrBfvMainTemplate;

impl MainTemplateGenerator<PkAggTrBfvTemplateParams> for PkAggTrBfvMainTemplate {
    fn generate_template(&self, params: &PkAggTrBfvTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use pk_agg_trbfv::{TrbfvPublicKeyAggregation, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for TrBFV Public Key Aggregation circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}>,
    pk0: [[Polynomial<{}>; {}]; {}],
    pk1: [[Polynomial<{}>; {}]; {}],
    pk0_agg: [Polynomial<{}>; {}],
    pk1_agg: [Polynomial<{}>; {}],
) {{
    // TODO: Your logic here...

    // Create Public Key Aggregation TRBFV circuit instance.
    let pk_agg_trbfv: TrbfvPublicKeyAggregation<{}, {}, {}> = TrbfvPublicKeyAggregation::new(
        params,
        pk0,
        pk1,
        pk0_agg,
        pk1_agg
    );

    // Verify aggregation
    pk_agg_trbfv.verify();

    // TODO: Your logic here...
}}"#,
            import_example,
            params.base.l,
            params.base.n,
            params.base.l,
            params.num_honest_parties,
            params.base.n,
            params.base.l,
            params.num_honest_parties,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.num_honest_parties,
            params.base.l,
        );

        Ok(template)
    }
}
