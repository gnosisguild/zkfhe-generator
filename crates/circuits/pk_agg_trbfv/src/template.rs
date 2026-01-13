use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

#[derive(Debug, Clone)]
pub struct PkAggTrBfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Bit width for public key bounds
    pub bit_pk: u32,
    /// Number of honest parties (H)
    pub num_honest_parties: usize,
    /// Parameter set (trbfv)
    pub parameter_set: String,
    /// Security level (production or insecure)
    pub security_level: String,
}

impl PkAggTrBfvTemplateParams {
    /// Create PkAggTrBfv template parameters from bounds
    pub fn new(
        base: BaseTemplateParams,
        num_honest_parties: usize,
        pk_bound: String,
        parameter_set: String,
        security_level: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit widths for each bound type
        let bit_pk = calculate_bit_width(&pk_bound)?;

        Ok(Self {
            base,
            bit_pk,
            num_honest_parties,
            parameter_set,
            security_level,
        })
    }
}

/// Generator for TrBFV Public Key Aggregation circuit main.nr templates
pub struct PkAggTrBfvMainTemplate;

impl MainTemplateGenerator<PkAggTrBfvTemplateParams> for PkAggTrBfvMainTemplate {
    fn generate_template(&self, params: &PkAggTrBfvTemplateParams) -> ZkFheResult<String> {
        let template = format!(
            r#"use lib::configs::{}::{}::{{
    N, L, PK_AGG_TRBFV_CONFIGS, PK_AGG_TRBFV_BIT_PK,
}};
use lib::core::trbfv_pk_agg::TrbfvPublicKeyAggregation;
use lib::math::polynomial::Polynomial;

/// Number of honest parties.
pub global H: u32 = {};

fn main(
    expected_pk_trbfv_commitments: [Field; H],
    pk0: [[Polynomial<N>; L]; H],
    pk1: [[Polynomial<N>; L]; H],
    pk0_agg: [Polynomial<N>; L],
    pk1_agg: [Polynomial<N>; L],
) -> pub Field {{
    let pk_agg_trbfv: TrbfvPublicKeyAggregation<N, H, L, PK_AGG_TRBFV_BIT_PK> = TrbfvPublicKeyAggregation::new(
        PK_AGG_TRBFV_CONFIGS,
        expected_pk_trbfv_commitments,
        pk0,
        pk1,
        pk0_agg,
        pk1_agg,
    );

    pk_agg_trbfv.verify()
}}"#,
            params.security_level, params.parameter_set, params.num_honest_parties,
        );

        Ok(template)
    }
}
