//! Main template generation for PVW circuit
//!
//! This module contains the main.nr template generation logic specific to the PVW circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the PVW circuit parameters.

use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator};

/// PVW-specific template parameters
///
/// This structure contains the parameters specific to the PVW circuit,
/// extending the base parameters with PVW-specific dimensions.
#[derive(Debug, Clone)]
pub struct PvwTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// LWE dimension (K)
    pub k: usize,
    /// Number of parties (N_PARTIES)
    pub n_parties: usize,
}

/// Generator for PVW circuit main.nr templates
pub struct PkPvwMainTemplate;

impl MainTemplateGenerator<PvwTemplateParams> for PkPvwMainTemplate {
    fn generate_template(&self, params: &PvwTemplateParams) -> ZkFheResult<String> {
        let import_example = "// use circuits::{crypto::pk_pvw::pk_pvw::{Params, PvwPublicKeyCircuit}, math::polynomial::Matrix};";

        let template = format!(
            r#"//! Generated main.nr template for PK PVW circuit
// TODO: Your imports here (example below)
{}

fn main(
    params: Params<{}, {}>,
    a: [Matrix<{}, {}, {}>; {}],
    e: Matrix<{}, {}, {}>,
    sk: Matrix<{}, {}, {}>, 
    b: [Matrix<{}, {}, {}>; {}],
    r1: [Matrix<{}, {}, {}>; {}],
    r2: [Matrix<{}, {}, {}>; {}],
    // TODO: Other parameters...
) {{
    // TODO: Your logic here...

    // Create PK PVW circuit instance.
    let pk_pvw: PvwPublicKeyCircuit<{}, {}, {}, {}> = PvwPublicKeyCircuit::new(params, a, e, sk, b, r1, r2);

    // TODO: Your logic here...
}}"#,
            import_example,
            params.base.n,
            params.base.l,
            params.k,
            params.k,
            params.base.n,
            params.base.l,
            params.n_parties,
            params.k,
            params.base.n,
            params.n_parties,
            params.k,
            params.base.n,
            params.n_parties,
            params.k,
            params.base.n,
            params.base.l,
            params.n_parties,
            params.k,
            2 * params.base.n - 1,
            params.base.l,
            params.n_parties,
            params.k,
            params.base.n - 1,
            params.base.l,
            params.base.n,
            params.base.l,
            params.k,
            params.n_parties
        );

        Ok(template)
    }
}
