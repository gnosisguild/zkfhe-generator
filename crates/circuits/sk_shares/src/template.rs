//! Main template generation for Secret Key Shares verification circuit
//!
//! This module contains the main.nr template generation logic specific to the Secret Key Shares circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Secret Key Shares circuit parameters.

use num_bigint::BigUint;
use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};

/// Secret Key Shares bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct SkSharesBoundsData {
    pub sk_bound: String,
    pub moduli: Vec<u64>,
}

/// Secret Key Shares-specific template parameters
///
/// This structure contains the parameters specific to the Secret Key Shares circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct SkSharesTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of parties (N_PARTIES)
    pub num_parties: usize,
    /// Threshold value (T)
    pub threshold: usize,
    /// Bit width for secret key (BIT_SK)
    pub bit_sk: u32,
    /// Bit width for shares (BIT_SHARE)
    pub bit_share: u32,
}

impl SkSharesTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_parties: usize,
        threshold: usize,
        bounds: &SkSharesBoundsData,
    ) -> ZkFheResult<Self> {
        // Calculate bit width for secret key bound
        let bit_sk = calculate_bit_width(&bounds.sk_bound)?;

        // Calculate bit width for shares directly from moduli
        // Share bound for each modulus q_j is q_j - 1 (since shares are in [0, q_j))
        let mut bit_share = 0;
        for &q_j in &bounds.moduli {
            let share_bound = BigUint::from(q_j - 1);
            let bit_width = calculate_bit_width(&share_bound.to_string())?;
            bit_share = bit_share.max(bit_width);
        }

        Ok(Self {
            base,
            num_parties,
            threshold,
            bit_sk,
            bit_share,
        })
    }
}

/// Generator for Secret Key Shares circuit main.nr templates
pub struct SkSharesMainTemplate;

impl MainTemplateGenerator<SkSharesTemplateParams> for SkSharesMainTemplate {
    fn generate_template(&self, params: &SkSharesTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use sk_shares::{SecretKeySharesVerificationCircuit, Params};
// use polynomial::Polynomial;";

        let template = format!(
            r#"//! Generated main.nr template for Secret Key Shares verification circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}>,
    sk: Polynomial<{}>,
    y: [[[Field; {}]; {}]; {}],
    h: [[[Field; {}]; {}]; {}],
) {{
    // TODO: Your logic here...

    // Create Secret Key Shares Verification circuit instance
    let sk_shares: SecretKeySharesVerificationCircuit<{}, {}, {}, {}, {}, {}> = 
        SecretKeySharesVerificationCircuit::new(
            params,
            sk,
            y,
            h,
        );

    // Verify correct secret key shares
    sk_shares.verify();

    // TODO: Your logic here...
}}"#,
            import_example,
            params.base.l,                         // L (number of moduli)
            params.base.n,                         // sk N (polynomial degree)
            params.num_parties + 1,                // y inner array size (N_PARTIES + 1)
            params.base.l,                         // y middle array size (L)
            params.base.n,                         // y outer array size (N)
            params.num_parties + 1,                // h inner array size (N_PARTIES + 1)
            params.num_parties - params.threshold, // h middle array size (N_PARTIES - T)
            params.base.l,                         // h outer array size (L)
            params.base.n,                         // Circuit N
            params.base.l,                         // Circuit L
            params.num_parties,                    // Circuit N_PARTIES
            params.threshold,                      // Circuit T
            params.bit_sk,                         // Circuit BIT_SK
            params.bit_share,                      // Circuit BIT_SHARE
        );

        Ok(template)
    }
}
