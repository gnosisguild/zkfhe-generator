use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// BFV Public Key bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct PkBfvBoundsData {
    /// Bound for public key polynomials (pk0, pk1)
    pub pk_bound: String,
}

#[derive(Debug, Clone)]
pub struct PkBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for public key (pk) bounds
    pub bit_pk: u32,
    /// Parameter set name (bfv)
    pub parameter_set: String,
    /// Security level (production or insecure) for import path
    /// "production" if lambda >= 80, "insecure" otherwise
    pub security_level: String,
}

impl PkBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        bounds: &PkBfvBoundsData,
        parameter_set: String,
        security_level: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit width for pk bound
        let bit_pk = calculate_bit_width(&bounds.pk_bound)?;

        Ok(Self {
            base,
            bit_pk,
            parameter_set,
            security_level,
        })
    }
}

/// Generator for BFV Public Key circuit main.nr templates
pub struct PkBfvMainTemplate;

impl MainTemplateGenerator<PkBfvTemplateParams> for PkBfvMainTemplate {
    fn generate_template(&self, params: &PkBfvTemplateParams) -> ZkFheResult<String> {
        let prefix = "PK_BFV";

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L, N, {}_BIT_PK,
}};
use lib::core::bfv_pk::BfvPkCommit;
use lib::math::polynomial::Polynomial;

fn main(
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
) -> pub Field {{
    let pk_bfv: BfvPkCommit<N, L, {}_BIT_PK> =
        BfvPkCommit::new(pk0is, pk1is);
    pk_bfv.verify()
}}
"#,
            params.security_level, params.parameter_set, prefix, prefix,
        );

        Ok(template)
    }
}
