use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Threshold BFV Public Key bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct PkTrBfvBoundsData {
    pub eek_bound: String,
    pub sk_bound: String,
    /// Bound for smudging noise polynomial (e_sm) coefficients
    pub e_sm_bound: String,
    pub r1_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
    /// Bound for public key polynomials (pk0, pk1)
    pub pk_bound: String,
}

#[derive(Debug, Clone)]
pub struct PkTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for eek bounds
    pub bit_eek: u32,
    /// Bit width for sk bounds
    pub bit_sk: u32,
    /// Bit width for smudging noise (e_sm) bounds
    pub bit_e_sm: u32,
    /// Bit width for r1 bounds
    pub bit_r1: u32,
    /// Bit width for r2 bounds
    pub bit_r2: u32,
    /// Bit width for public key (pk) bounds
    pub bit_pk: u32,
    /// Parameter set name (only trbfv is supported now)
    pub parameter_set: String,
    /// Security level (production or insecure) for import path
    /// "production" if lambda >= 80, "insecure" otherwise
    pub security_level: String,
}

impl PkTrBfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        bounds: &PkTrBfvBoundsData,
        parameter_set: String,
        security_level: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_eek = calculate_bit_width(&bounds.eek_bound)?;
        let bit_sk = calculate_bit_width(&bounds.sk_bound)?;
        let bit_e_sm = calculate_bit_width(&bounds.e_sm_bound)?;
        let bit_pk = calculate_bit_width(&bounds.pk_bound)?;

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
            bit_e_sm,
            bit_r1,
            bit_r2,
            bit_pk,
            parameter_set,
            security_level,
        })
    }
}

/// Generator for Threshold BFV Public Key circuit main.nr templates
pub struct PkTrBfvMainTemplate;

impl MainTemplateGenerator<PkTrBfvTemplateParams> for PkTrBfvMainTemplate {
    fn generate_template(&self, params: &PkTrBfvTemplateParams) -> ZkFheResult<String> {
        // Only TRBFV is supported now
        let prefix = "PK_TRBFV";
        let var_name = "pk_trbfv";

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L, N, {}_BIT_EEK, {}_BIT_SK, {}_BIT_E_SM, {}_BIT_R1, {}_BIT_R2, {}_BIT_PK, {}_CONFIGS,
}};
use lib::core::trbfv_pk::TrbfvPublicKey;
use lib::math::polynomial::Polynomial;

fn main(
    a: pub [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    e_sm: [Polynomial<N>, L],
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
) -> pub (Field, Field, Field) {{
    let {}: TrbfvPublicKey<N, L, {}_BIT_EEK, {}_BIT_SK, {}_BIT_E_SM, {}_BIT_R1, {}_BIT_R2, {}_BIT_PK> =
        TrbfvPublicKey::new({}_CONFIGS, a, eek, sk, e_sm, r1is, r2is, pk0is, pk1is);
    {}.verify()
}}"#,
            params.security_level,
            params.parameter_set,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            var_name,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            prefix,
            var_name,
        );

        Ok(template)
    }
}
