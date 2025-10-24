use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator};

/// TrBFV Public Key bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct PkTrBfvBoundsData {
    pub eek_bound: String,
    pub sk_bound: String,
    pub r1_low_bounds: Vec<String>,
    pub r1_up_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PkTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
}

impl PkTrBfvTemplateParams {
    pub fn new(base: BaseTemplateParams) -> ZkFheResult<Self> {
        Ok(Self { base })
    }
}

/// Generator for TrBFV Public Key circuit main.nr templates
pub struct PkTrBfvMainTemplate;

impl MainTemplateGenerator<PkTrBfvTemplateParams> for PkTrBfvMainTemplate {
    fn generate_template(&self, params: &PkTrBfvTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use pk_trbfv::{BfvPublicKeyCircuit, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for TrBFV Public Key circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}>,
    a: [Polynomial<{}>; {}],
    eek: Polynomial<{}>,
    sk: Polynomial<{}>,
    r1is: [Polynomial<{}>; {}],
    r2is: [Polynomial<{}>; {}],
    pk0is: [Polynomial<{}>; {}],
    pk1is: [Polynomial<{}>; {}],
    // TODO: Other parameters...
) {{
    // TODO: Your logic here...

    // Create PkTrBfv circuit instance.
    let pk_trbfv: BfvPublicKeyCircuit<{}, {}> = BfvPublicKeyCircuit::new(
        params,
        a,
        eek,
        sk,
        r1is,
        r2is,
        pk0is,
        pk1is
    );

    // TODO: Your logic here...
    }}"#,
            import_example,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.n,
            2 * params.base.n - 1,
            params.base.l,
            params.base.n - 1,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
            params.base.n,
            params.base.l,
        );

        Ok(template)
    }
}
