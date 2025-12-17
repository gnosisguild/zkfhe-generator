use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// BFV Public Key bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct PkBfvBoundsData {
    pub eek_bound: String,
    pub sk_bound: String,
    pub r1_bounds: Vec<String>,
    pub r2_bounds: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PkBfvTemplateParams {
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
    /// Parameter set name (trbfv or bfv) for import path and constant names
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
            parameter_set,
            security_level,
        })
    }
}

/// Generator for BFV Public Key circuit main.nr templates
pub struct PkBfvMainTemplate;

impl MainTemplateGenerator<PkBfvTemplateParams> for PkBfvMainTemplate {
    fn generate_template(&self, params: &PkBfvTemplateParams) -> ZkFheResult<String> {
        // Determine constant prefix based on parameter set
        let prefix = if params.parameter_set == "trbfv" {
            "PK_TRBFV"
        } else {
            "PK_BFV"
        };

        // Determine variable name based on parameter set
        let var_name = if params.parameter_set == "trbfv" {
            "pk_trbfv"
        } else {
            "pk_bfv"
        };

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L, N, {}_BIT_EEK, {}_BIT_R1, {}_BIT_R2, {}_BIT_SK, {}_CONFIGS,
}};
use lib::core::bfv_pk::BfvPublicKey;
use lib::math::polynomial::Polynomial;

fn main(
    a: [Polynomial<N>; L],
    eek: Polynomial<N>,
    sk: Polynomial<N>,
    r1is: [Polynomial<(2 * N) - 1>; L],
    r2is: [Polynomial<N - 1>; L],
    pk0is: [Polynomial<N>; L],
    pk1is: [Polynomial<N>; L],
) -> pub Field {{
    let {}: BfvPublicKey<N, L, {}_BIT_EEK, {}_BIT_SK, {}_BIT_R1, {}_BIT_R2> =
        BfvPublicKey::new({}_CONFIGS, a, eek, sk, r1is, r2is, pk0is, pk1is);
    {}.verify()
}}"#,
            params.security_level,
            params.parameter_set,
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
            var_name,
        );

        Ok(template)
    }
}
