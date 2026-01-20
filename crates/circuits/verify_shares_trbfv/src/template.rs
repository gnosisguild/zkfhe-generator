//! Main template generation for Secret Key Shares verification circuit
//!
//! This module contains the main.nr template generation logic specific to the Secret Key Shares circuit.
//! It generates a template with the correct parameter types and function signature
//! based on the Secret Key Shares circuit parameters.

use num_bigint::{BigInt, BigUint};
use parity_matrix::matrix::{ParityMatrixConfig, build_generator_matrix, null_space};
use shared::errors::ZkFheResult;
use shared::template::{BaseTemplateParams, MainTemplateGenerator, calculate_bit_width};
use shared::utils::bigint_to_field;

/// Verify Shares TRBFV bounds data for template parameter calculation
#[derive(Debug, Clone)]
pub struct VerifySharesTrbfvBoundsData {
    pub sk_bound: String,
    pub secret_bound: String, // Actual bound for secret (either sk_bound or e_sm_bound)
    pub moduli: Vec<u64>,
}

/// Verify Shares TRBFV-specific template parameters
///
/// This structure contains the parameters specific to the Verify Shares TRBFV circuit,
/// extending the base parameters with circuit-specific bit-widths and bounds.
#[derive(Debug, Clone)]
pub struct VerifySharesTrbfvTemplateParams {
    /// Base parameters (N, L, circuit_type)
    pub base: BaseTemplateParams,
    /// Number of parties (N_PARTIES)
    pub num_parties: usize,
    /// Threshold value (T)
    pub threshold: usize,
    /// Bit width for secret (BIT_SECRET)
    pub bit_secret: u32,
    /// Bit width for shares (BIT_SHARE)
    pub bit_share: u32,
    /// Parameter set name (trbfv or bfv) for import path
    pub parameter_set: String,
    /// Security level (secure or insecure) for import path
    /// "production" for SET_8192_100_4, "insecure" otherwise
    pub security_level: String,
    /// Secret type postfix ("SK" or "ESM") for config names
    pub secret_type_postfix: String,
    /// Bounds data containing moduli for parity matrix generation
    pub bounds_data: VerifySharesTrbfvBoundsData,
}

impl VerifySharesTrbfvTemplateParams {
    pub fn from_bounds(
        base: BaseTemplateParams,
        num_parties: usize,
        threshold: usize,
        bounds: &VerifySharesTrbfvBoundsData,
        parameter_set: String,
        security_level: String,
    ) -> ZkFheResult<Self> {
        // Calculate bit width for secret bound (use secret_bound which may be smudging bound)
        let bit_secret = calculate_bit_width(&bounds.secret_bound)?;

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
            bit_secret,
            bit_share,
            parameter_set,
            security_level,
            secret_type_postfix: String::new(), // Will be set by caller
            bounds_data: bounds.clone(),
        })
    }
}

/// Generator for Verify Shares TRBFV circuit main.nr templates
pub struct VerifySharesTrbfvMainTemplate;

impl MainTemplateGenerator<VerifySharesTrbfvTemplateParams> for VerifySharesTrbfvMainTemplate {
    fn generate_template(&self, params: &VerifySharesTrbfvTemplateParams) -> ZkFheResult<String> {
        let bit_secret_name = format!("VERIFY_SHARES_BIT_SECRET_{}", params.secret_type_postfix);
        let configs_name = format!("VERIFY_SHARES_CONFIGS_{}", params.secret_type_postfix);

        // Determine which verification function to use:
        // Since we normalize y[i][j][0] = secret[i] mod q_j in Rust, values are kept small.
        // We use ModU128 for all cases to keep circuit size manageable.
        // Note: q_j values for production are typically < 2^52, so normalized values should fit in U128.
        let verify_call = "verify_shares.verify()";

        // Generate template based on secret type (SK vs ESM)
        let (secret_param, struct_type, constructor_param) = if params.secret_type_postfix == "SK" {
            // For SK: secret_sk: Polynomial<N> (single polynomial, no L dimension)
            (
                "secret_sk: Polynomial<N>".to_string(),
                "VerifySharesSk".to_string(),
                "secret_sk".to_string(),
            )
        } else {
            // For ESM: secret_e_sm: [Polynomial<N>; L] (array of polynomials)
            (
                "secret_e_sm: [Polynomial<N>; L]".to_string(),
                "VerifySharesEsm".to_string(),
                "secret_e_sm".to_string(),
            )
        };

        // Generate parity matrix for each modulus
        // h[mod_idx][row][col] where size is [L][N_PARTIES-T][N_PARTIES+1]
        let mut parity_matrix_strings = Vec::new();
        for &q_j in &params.bounds_data.moduli {
            let config = ParityMatrixConfig {
                q: BigUint::from(q_j),
                t: params.threshold,
                n: params.num_parties,
            };

            let g = build_generator_matrix(config.clone()).map_err(|e| {
                shared::errors::ZkFheError::Bfv {
                    message: format!("Failed to build generator matrix: {:?}", e),
                }
            })?;

            let h_mod = null_space(&g, &config.q).map_err(|e| shared::errors::ZkFheError::Bfv {
                message: format!("Failed to compute null space: {:?}", e),
            })?;

            // Convert to Field values and format as Noir array
            let mut modulus_rows = Vec::new();
            for row in &h_mod {
                let mut row_values = Vec::new();
                for val in row {
                    // Convert BigUint to BigInt (non-negative, so safe)
                    let bigint_val = BigInt::from(val.clone());
                    let field_val = bigint_to_field(&bigint_val);
                    row_values.push(format!("{}", field_val));
                }
                modulus_rows.push(format!("[{}]", row_values.join(", ")));
            }
            parity_matrix_strings.push(format!("[{}]", modulus_rows.join(",\n        ")));
        }

        let parity_matrix_constant = format!(
            "pub global H: [[[Field; N_PARTIES + 1]; N_PARTIES - T]; L] = [\n    {}];",
            parity_matrix_strings.join(",\n    ")
        );

        let template = format!(
            r#"use lib::configs::{}::{}::{{
    L, N, VERIFY_SHARES_BIT_SHARE, {}, {},
}};
use lib::core::trbfv_verify_shares::{};
use lib::math::polynomial::Polynomial;

/// Number of parties.
pub global N_PARTIES: u32 = {};
/// Threshold.
pub global T: u32 = {};
/// Parity check matrix for each modulus.
/// H[modulus_idx][row][col] where size is [L][N_PARTIES-T][N_PARTIES+1]
{}

fn main(
    expected_secret_commitment: pub Field,
    {},
    y: [[[Field; N_PARTIES + 1]; L]; N],
) -> pub [[Field; L]; N_PARTIES] {{
    let verify_shares: {}<N, L, N_PARTIES, T, {}, VERIFY_SHARES_BIT_SHARE>
         = {}::new({}, expected_secret_commitment, {}, y, H);

    {}
}}"#,
            params.security_level,
            params.parameter_set,
            bit_secret_name,
            configs_name,
            struct_type,
            params.num_parties,
            params.threshold,
            parity_matrix_constant,
            secret_param,
            struct_type,
            bit_secret_name,
            struct_type,
            configs_name,
            constructor_param,
            verify_call,
        );

        Ok(template)
    }
}
