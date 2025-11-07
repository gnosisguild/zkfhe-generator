use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// TrBFV Public Key bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct PkTrBfvBoundsData {
    pub eek_bound: String,
    pub sk_bound: String,
    pub r1_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PkTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for eek bounds
    pub bit_eek: u32,
    /// Bit width for sk bounds
    pub bit_sk: u32,
    /// Bit width for r1 bounds
    pub bit_r1: u32,
    /// Bit width for r2 bounds
    pub bit_r2: u32,
}

impl PkTrBfvTemplateParams {
    pub fn from_bounds(base: BaseTemplateParams, bounds: &PkTrBfvBoundsData) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_eek = calculate_bit_width(&bounds.eek_bound)?;
        let bit_sk = calculate_bit_width(&bounds.sk_bound)?;

        // For r1, use the maximum of all low and up bounds
        let mut bit_r1 = 0;
        for bound in &bounds.r1_bounds {
            bit_r1 = bit_r1.max(calculate_bit_width(bound)?);
        }

        // For r2, use the maximum of all bounds
        let mut bit_r2 = 0;
        for bound in &bounds.r2_bounds {
            bit_r2 = bit_r2.max(calculate_bit_width(bound)?);
        }

        Ok(Self {
            base,
            bit_eek,
            bit_sk,
            bit_r1,
            bit_r2,
        })
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

    // Create Public Key TRBFV circuit instance.
    let pk_trbfv: BfvPublicKeyCircuit<{}, {}, {}, {}, {}, {}> = BfvPublicKeyCircuit::new(
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
            params.bit_eek,
            params.bit_sk,
            params.bit_r1,
            params.bit_r2,
        );

        Ok(template)
    }
}
