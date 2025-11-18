//! zkFHE Generator CLI
//!
//! Command-line tool for generating zkFHE circuit parameters and TOML files.
//!
//! This binary provides a user-friendly interface for generating cryptographic
//! parameters and TOML files for zkFHE circuits. It supports multiple circuits,
//! preset configurations for different security levels, and flexible parameter types.
//!
//! - **Circuit Registry**: Easy registration and management of circuit implementations
//! - **Preset System**: Pre-configured security levels (dev, test, prod)
//! - **Parameter Types**: Support for trBFV and BFV parameter generation
//! - **Validation**: Comprehensive parameter validation and error handling
//! - **Beautiful Output**: Emoji-rich progress indicators and user feedback
use clap::{Args, Parser, Subcommand};
use num_bigint::BigUint;
use std::path::{Path, PathBuf};

use crypto_params::bfv::{BfvSearchConfig, bfv_search, bfv_search_second_param};
use crypto_params::utils::approx_bits_from_log2;
use crypto_params::utils::fmt_big_summary;
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use shared::circuit::{ParameterType, SampleType};
use shared::utils::{variance_uniform_sym_str_big, variance_uniform_sym_str_u128};
use shared::{BaseTemplateParams, Circuit, MainTemplateGenerator};
use std::sync::Arc;

/// Main CLI structure using clap for argument parsing
///
/// This structure defines the command-line interface using clap's derive macros.
/// It provides a clean, type-safe way to handle command-line arguments and
/// subcommands.
#[derive(Parser)]
#[command(name = "zkfhe-generator")]
#[command(about = "Generate zkFHE circuit parameters and TOML files")]
struct Cli {
    /// The subcommand to execute
    #[command(subcommand)]
    command: Commands,
}

/// Available CLI commands
///
/// This enum defines all the available commands that the CLI supports.
/// Each command has its own set of arguments and options.
#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Generate parameters for a specific circuit
    ///
    /// This command generates cryptographic parameters and TOML files
    /// for the specified circuit. You can either use a preset configuration
    /// or specify custom BFV parameters directly.
    Generate {
        /// Circuit name to generate parameters for
        ///
        /// This should match the name returned by the circuit's `name()` method.
        /// Available circuits can be listed using the `list` command.
        #[arg(long, short)]
        circuit: String,

        /// Preset configuration (dev, test, prod)
        ///
        /// The preset determines the security level and cryptographic parameters
        /// used for generation. If not specified, defaults to "dev".
        /// Custom parameters (--bfv-*) will override preset values.
        #[arg(long, short)]
        preset: Option<String>,

        /// BFV-specific parameters
        ///
        /// Use these flags to specify BFV (Brakerski-Fan-Vercauteren) parameters.
        /// This is the default parameter type for most circuits.
        #[command(flatten)]
        bfv: Option<BfvParams>,

        /// Parameter type to generate
        ///
        /// Choose between trBFV (threshold BFV, stricter security, 40-61 bit primes) and BFV
        /// (simpler conditions, 40-63 bit primes including 62-bit primes).
        /// Available parameter types can be listed using the `list` command.
        #[arg(long, short = 't', required = true)]
        parameter_type: String,

        /// Verbose output showing detailed parameter search process
        #[arg(long, short)]
        verbose: bool,

        /// Output directory for generated files
        ///
        /// The directory where the generated TOML file will be placed.
        /// If not specified, defaults to the current directory.
        #[arg(long, short, default_value = ".")]
        output: PathBuf,

        /// Generate template main.nr file
        ///
        /// When enabled, generates a template main.nr file with the correct
        /// function signature and parameter types for the specified circuit.
        /// The template will be parameterized with the generated cryptographic
        /// parameters (N, L, K, N_PARTIES, etc.).
        #[arg(long)]
        main: bool,

        /// Sample type for share_row generation (Greco circuit only)
        ///
        /// This option is only applicable to the greco circuit with BFV parameter type.
        /// Determines what type of share_row to generate:
        /// - `secret-key`: Generate sk_sss share_row (default)
        /// - `smudging-noise`: Generate es_sss share_row
        ///
        /// This affects the type of threshold share that gets encrypted in Circuit 4.
        #[arg(long, default_value = "secret-key")]
        sample_type: String,
    },

    /// List available circuits and presets
    ///
    /// This command displays information about available circuits and
    /// preset configurations.
    List {
        /// List available circuits
        #[arg(long)]
        circuits: bool,

        /// List available presets
        #[arg(long)]
        presets: bool,
    },
}

/// BFV-specific parameters
#[derive(Args, Debug, Clone)]
pub struct BfvParams {
    /// Number of parties n (e.g. ciphernodes)
    ///
    /// This parameter affects the security analysis and noise bounds.
    /// If not specified, uses the preset default or 1000.
    #[arg(long)]
    n: Option<u128>,

    /// Number of fresh ciphertext additions z (number of votes)
    ///
    /// Note that the BFV plaintext modulus k will be defined as k = z.
    /// If not specified, uses the preset default or 1000.
    #[arg(long)]
    z: Option<u128>,

    /// Plaintext modulus k (plaintext space).
    ///
    /// If not specified, uses the preset default or 1000.
    #[arg(long)]
    k: Option<u128>,

    /// Statistical Security parameter λ (negl(λ)=2^{-λ})
    ///
    /// Higher values provide stronger security guarantees but may require
    /// larger parameters. If not specified, uses the preset default or 80.
    #[arg(long)]
    lambda: Option<u32>,

    /// Bound B on the error distribution ψ
    ///
    /// Used to generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    /// If not specified, uses the preset default or 20.
    #[arg(long)]
    b: Option<u128>,

    /// Bound B_{\chi} on the distribution \chi used generate the secret key sk_i of each party i.
    ///
    /// If not specified, uses the preset default or 1.
    #[arg(long)]
    b_chi: Option<u128>,
}

/// Circuit registry - maps circuit names to their implementations
///
/// This function provides a centralized registry of all available circuit
/// implementations. To add a new circuit, simply add a new match arm here.
///
/// # Arguments
///
/// * `circuit_name` - The name of the circuit to load
/// * `parameter_type` - The parameter type (BFV or trBFV)
/// * `sample_type` - The sample type (only used for greco circuit)
///
/// # Returns
///
/// Returns a boxed circuit implementation or an error if the circuit is not found.
fn get_circuit(
    circuit_name: &str,
    parameter_type: ParameterType,
    sample_type: SampleType,
) -> anyhow::Result<Box<dyn Circuit>> {
    match circuit_name.to_lowercase().as_str() {
        "greco" => {
            let circuit = greco::circuit::GrecoCircuit::new(parameter_type, sample_type);
            Ok(Box::new(circuit))
        }
        "pk-trbfv" => {
            let circuit = pk_trbfv::circuit::PkTrBfvCircuit::new(parameter_type);
            Ok(Box::new(circuit))
        }
        "dec-share-trbfv" => {
            let circuit = dec_share_trbfv::circuit::DecShareTrBfvCircuit::new(parameter_type);
            Ok(Box::new(circuit))
        }
        _ => anyhow::bail!("Unknown circuit: {circuit_name}"),
    }
}

/// Get supported parameter types per circuit.
pub fn get_supported_parameter_types_per_circuit(circuit_name: &str) -> Vec<ParameterType> {
    match circuit_name.to_lowercase().as_str() {
        "greco" => vec![ParameterType::Trbfv, ParameterType::Bfv],
        "pk-trbfv" => vec![ParameterType::Trbfv, ParameterType::Bfv],
        "dec-share-trbfv" => vec![ParameterType::Trbfv],
        // Future circuits can support different parameter types
        _ => vec![],
    }
}

/// Check if a parameter type is compatible with a circuit.
pub fn is_compatible(circuit_name: &str, param_type: &ParameterType) -> bool {
    get_supported_parameter_types_per_circuit(circuit_name).contains(param_type)
}

/// Create BFV search configuration from CLI arguments
fn create_bfv_config(
    preset: Option<&str>,
    bfv_params: Option<BfvParams>,
    verbose: bool,
) -> anyhow::Result<BfvSearchConfig> {
    // Start with preset defaults
    let mut config = match preset.unwrap_or("SET_8192_1000_4") {
        // dev would be hardcoded later in the code based on current development parameters for Enclave.
        // degree: 2048
        // plaintext_modulus: 1032193
        // moduli: [0x3FFFFFFF000001]
        "INSECURE_SET_2048_1032193_1" => BfvSearchConfig {
            // irrelevant since will be overridden by hardcoded values later in the code.
            n: 1,
            k: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        // degree: 512
        // plaintext_modulus: 10
        // moduli: [0xffffee001, 0xffffc4001]
        // paired with InsecureSet512_0xffffee001_1
        "INSECURE_SET_512_10_1" => BfvSearchConfig {
            // irrelevant since will be overridden by hardcoded values later in the code.
            n: 1,
            k: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        // 128b security with multiple parties 1000 (for production purposes).
        // paired with Set8192_144115188075855872_2
        "SET_8192_1000_4" => BfvSearchConfig {
            // irrelevant since will be overridden by hardcoded values later in the code.
            n: 1000,
            k: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        // 128b security with multiple parties 100 (for production purposes).
        // paired with Set8192_144115188075855872_2
        "SET_8192_100_4" => BfvSearchConfig {
            // irrelevant since will be overridden by hardcoded values later in the code.
            n: 100,
            k: 100,
            z: 100,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        _ => anyhow::bail!("Unknown preset: {}", preset.unwrap()),
    };

    // Override with custom values if provided
    if let Some(bfv_params) = bfv_params {
        if let Some(n_val) = bfv_params.n {
            config.n = n_val;
        }
        if let Some(k_val) = bfv_params.k {
            config.k = k_val;
        }
        if let Some(z_val) = bfv_params.z {
            config.z = z_val;
        }
        if let Some(lambda_val) = bfv_params.lambda {
            config.lambda = lambda_val;
        }
        if let Some(b_val) = bfv_params.b {
            config.b = b_val;
        }
        if let Some(b_chi_val) = bfv_params.b_chi {
            config.b_chi = b_chi_val;
        }
    }

    Ok(config)
}

/// Generate parameters for a circuit
///
/// This function orchestrates the entire parameter generation process:
/// 1. Loads the specified circuit implementation
/// 2. Creates the BFV configuration from the preset
/// 3. Generates circuit parameters
/// 4. Creates the TOML file
fn generate_circuit_params(
    circuit_name: &str,
    preset: Option<&str>,
    parameter_type: ParameterType,
    verbose: bool,
    output_dir: &Path,
    generate_main: bool,
    sample_type: SampleType,
) -> anyhow::Result<()> {
    if let Some(preset_name) = preset {
        println!("📋 Using preset: {preset_name}");
    }

    println!("📋 Using parameter type: {}", parameter_type.as_str());

    // Get circuit implementation
    let circuit = get_circuit(circuit_name, parameter_type, sample_type)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    if !is_compatible(circuit_name, &parameter_type) {
        anyhow::bail!("Parameter type is not compatible with circuit");
    }

    let (trbfv_params, bfv_params): (Arc<BfvParameters>, Arc<BfvParameters>) =
        if preset == Some("INSECURE_SET_2048_1032193_1") {
            // Hardcode INSECURE_SET_2048_1032193_1 parameters based on current development parameters for Enclave.
            let params = BfvParametersBuilder::new()
                .set_degree(2048)
                .set_plaintext_modulus(1032193)
                .set_moduli(&[0x3FFFFFFF000001])
                .build_arc()
                .unwrap();

            (params.clone(), params.clone())
        } else if preset == Some("INSECURE_SET_512_10_1") {
            // Hardcode INSECURE_SET_512_10_1 parameters based on current development parameters for Enclave.
            let params_trbfv = BfvParametersBuilder::new()
                .set_degree(512)
                .set_plaintext_modulus(10)
                .set_moduli(&[0xffffee001, 0xffffc4001])
                .set_error1_variance(BigUint::from(3u32))
                .build_arc()
                .unwrap();

            let params_bfv = BfvParametersBuilder::new()
                .set_degree(512)
                .set_plaintext_modulus(0xffffee001)
                .set_moduli(&[0x7fffffffe0001])
                .build_arc()
                .unwrap();

            (params_trbfv.clone(), params_bfv.clone())
        } else if preset == Some("SET_8192_1000_4") {
            // Hardcode SET_8192_1000_4 parameters based on current development parameters for Enclave.
            let params_trbfv = BfvParametersBuilder::new()
                .set_degree(8192)
                .set_plaintext_modulus(1000)
                .set_moduli(&[
                    0x00800000022a0001,
                    0x00800000021a0001,
                    0x0080000002120001,
                    0x0080000001f60001,
                ])
                .set_error1_variance_str(
                    "52309181128222339698631578526730685514457152477762943514050560000",
                )
                .unwrap()
                .build_arc()
                .unwrap();

            let params_bfv = BfvParametersBuilder::new()
                .set_degree(8192)
                .set_plaintext_modulus(144115188075855872)
                .set_moduli(&[0x0400000001460001, 0x0400000000ea0001])
                .build_arc()
                .unwrap();

            (params_trbfv.clone(), params_bfv.clone())
        } else if preset == Some("SET_8192_100_4") {
            // Hardcode SET_8192_100_4 parameters based on current development parameters for Enclave.
            let params_trbfv = BfvParametersBuilder::new()
                .set_degree(8192)
                .set_plaintext_modulus(100)
                .set_moduli(&[
                    0x0008000000820001,
                    0x0010000000060001,
                    0x00100000003e0001,
                    0x00100000006e0001,
                ])
                .set_error1_variance_str(
                    "1004336277661868922213726307713258317841382576849282939643494400",
                )
                .unwrap()
                .build_arc()
                .unwrap();

            let params_bfv = BfvParametersBuilder::new()
                .set_degree(8192)
                .set_plaintext_modulus(18014398509481984)
                .set_moduli(&[0x0100000002a20001, 0x0100000001760001])
                .build_arc()
                .unwrap();

            (params_trbfv.clone(), params_bfv.clone())
        } else {
            // Create parameter configuration
            let param_config = create_bfv_config(preset, None, verbose)?;

            // Generate BFV parameters (always needed)
            println!(
                "🔐 BFV Configuration: n={}, z={}, k={}, λ={}, B={}, B_chi={}",
                param_config.n,
                param_config.z,
                param_config.k,
                param_config.lambda,
                param_config.b,
                param_config.b_chi
            );
            println!("⚙️  Searching for optimal BFV parameters...");

            let trbfv = bfv_search(&param_config)?;

            // Decide distributions for B and B_chi per your rule:
            // CBD for B when Var_CBD = B/2 ≤ 16  <=>  B ≤ 32, otherwise Uniform over [-B..B]
            let (dist_b, var_b) = if param_config.b <= 32 {
                // CBD for small bounds
                let var = if param_config.b % 2 == 0 {
                    (param_config.b / 2).to_string()
                } else {
                    format!("{}/2", param_config.b)
                };
                ("CBD".to_string(), var)
            } else {
                // Uniform otherwise
                (
                    "Uniform".to_string(),
                    variance_uniform_sym_str_u128(param_config.b),
                )
            };

            // B_chi stays CBD with variance B_chi/2
            let (dist_b_chi, var_chi) = (
                "CBD".to_string(),
                if param_config.b_chi % 2 == 0 {
                    (param_config.b_chi / 2).to_string()
                } else {
                    format!("{}/2", param_config.b_chi)
                },
            );

            // BEnc is treated as uniform over [-BEnc..BEnc] for variance reporting
            let (dist_benc, var_benc) = (
                "Uniform".to_string(),
                variance_uniform_sym_str_big(&trbfv.benc_min),
            );

            if verbose {
                println!("\n=== FIRST BFV PARAMETER SET ===");
                println!(
                    "n (number of ciphernodes)                = {}",
                    param_config.n
                );
                println!(
                    "z (number of votes)                      = {}",
                    param_config.z
                );
                println!(
                    "k (plaintext space)                      = {} ({} bits)",
                    trbfv.k_plain_eff,
                    approx_bits_from_log2((trbfv.k_plain_eff as f64).log2())
                );
                println!(
                    "λ (Statistical security parameter)       = {}",
                    param_config.lambda
                );
                println!(
                    "B (bound on e1)     = {}   [Dist: {}, Var = {}]",
                    param_config.b, dist_b, var_b
                );
                println!(
                    "B_chi (bound on sk) = {}   [Dist: {}, Var = {}]",
                    param_config.b_chi, dist_b_chi, var_chi
                );
                println!("d (LWE dimension)               = {}", trbfv.d);
                println!("q_BFV (decimal)  = {}", trbfv.q_bfv.to_str_radix(10));
                println!("|q_BFV|          = {}", fmt_big_summary(&trbfv.q_bfv));
                println!("Δ (decimal)      = {}", trbfv.delta.to_str_radix(10));
                println!("r_k(q)           = {}", trbfv.rkq);
                println!(
                    "BEnc (bound on e0)  = {}   [Dist: {}, Var = {}]",
                    trbfv.benc_min.to_str_radix(10),
                    dist_benc,
                    var_benc
                );
                println!("B_fresh          = {}", trbfv.b_fresh.to_str_radix(10));
                println!("B_C              = {}", trbfv.b_c.to_str_radix(10));
                println!("B_sm         = {}", trbfv.b_sm_min.to_str_radix(10));
                println!("log2(LHS)        = {:.6}", trbfv.lhs_log2);
                println!("log2(Δ)          = {:.6}", trbfv.rhs_log2);
                println!(
                    "q_i used ({}): {}",
                    trbfv.selected_primes.len(),
                    trbfv
                        .selected_primes
                        .iter()
                        .map(|p| format!("{} ({} bits)", p.hex, p.bitlen))
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }

            // Choose which parameter set to use based on parameter type
            let final_trbfv_params = trbfv.clone();
            let final_bfv_params = bfv_search_second_param(&param_config, &trbfv)
                .ok_or_else(|| anyhow::anyhow!("No second BFV parameter set found"))?;

            let trbfv_params = BfvParametersBuilder::new()
                .set_degree(final_trbfv_params.d as usize)
                .set_plaintext_modulus(final_trbfv_params.k_plain_eff as u64)
                .set_moduli(final_trbfv_params.qi_values().as_slice())
                .set_variance(var_b.parse::<usize>().unwrap())
                .set_error1_variance_str(var_benc.as_str())?
                .build_arc()
                .unwrap();
            let bfv_params = BfvParametersBuilder::new()
                .set_degree(final_bfv_params.d as usize)
                .set_plaintext_modulus(final_bfv_params.k_plain_eff as u64)
                .set_moduli(final_bfv_params.qi_values().as_slice())
                .build_arc()
                .unwrap();
            (trbfv_params, bfv_params)
        };

    if parameter_type == ParameterType::Trbfv {
        println!(
            "🔐 {} Parameters: degree={}, plaintext_modulus={}, moduli=[{}]",
            parameter_type.as_str(),
            trbfv_params.degree(),
            trbfv_params.plaintext(),
            trbfv_params
                .moduli()
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    } else {
        println!(
            "🔐 {} Parameters: degree={}, plaintext_modulus={}, moduli=[{}]",
            parameter_type.as_str(),
            bfv_params.degree(),
            bfv_params.plaintext(),
            bfv_params
                .moduli()
                .iter()
                .map(|m| m.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Generate TOML file
    println!("📄 Generating TOML file...");
    circuit
        .generate_toml(&trbfv_params, &bfv_params, output_dir)
        .map_err(|e| anyhow::anyhow!("Failed to generate TOML: {e}"))?;
    println!("✅ TOML file generated successfully");

    // Generate main.nr template if requested
    if generate_main {
        println!("📄 Generating main.nr template...");
        if circuit.parameter_type() == ParameterType::Trbfv {
            generate_main_template(circuit.as_ref(), &trbfv_params, output_dir)?;
        } else {
            generate_main_template(circuit.as_ref(), &bfv_params, output_dir)?;
        }
        println!("✅ main.nr template generated successfully");
    }

    println!("\n🎉 Generation complete!");
    println!("📁 Output directory: {}", output_dir.display());

    Ok(())
}

/// Generate main.nr template for the specified circuit
///
/// This function extracts the necessary parameters from the generated cryptographic
/// parameters and generates a template main.nr file with the correct function signature
/// and parameter types for the specified circuit.
fn generate_main_template(
    circuit: &dyn Circuit,
    bfv_params: &Arc<BfvParameters>,
    output_dir: &Path,
) -> anyhow::Result<()> {
    // Extract base parameters (N, L) that are common to all circuits
    let l = bfv_params.moduli().len();
    let circuit_type = circuit.name();

    // Generate circuit-specific template based on circuit type
    match circuit_type {
        "greco" => {
            use greco::bounds::GrecoBounds;
            use greco::template::{GrecoMainTemplate, GrecoTemplateParams};

            let (_, bounds) = GrecoBounds::compute(bfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute Greco bounds: {e:?}"))?;

            let bounds_data = greco::template::GrecoBoundsData {
                pk_bounds: bounds.pk_bounds.iter().map(|b| b.to_string()).collect(),
                ct_bounds: bounds.pk_bounds.iter().map(|b| b.to_string()).collect(), // Same as pk_bounds
                u_bound: bounds.u_bound.to_string(),
                e0_bound: bounds.e0_bound.to_string(),
                e1_bound: bounds.e1_bound.to_string(),
                k1_low_bound: bounds.k1_low_bound.to_string(),
                k1_up_bound: bounds.k1_up_bound.to_string(),
                r1_low_bounds: bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect(),
                r1_up_bounds: bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
                p1_bounds: bounds.p1_bounds.iter().map(|b| b.to_string()).collect(),
                p2_bounds: bounds.p2_bounds.iter().map(|b| b.to_string()).collect(),
            };

            let greco_template_params = GrecoTemplateParams::from_bounds(
                BaseTemplateParams::new(bfv_params.degree(), l, circuit_type),
                &bounds_data,
            )?;

            let template_generator = GrecoMainTemplate;
            template_generator.generate_main_file(&greco_template_params, output_dir)?;
        }
        "pk-trbfv" => {
            use pk_trbfv::bounds::PkTrBfvBounds;
            use pk_trbfv::template::{PkTrBfvMainTemplate, PkTrBfvTemplateParams};

            let (_, bounds) = PkTrBfvBounds::compute(bfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute PkTrBfv bounds: {e:?}"))?;

            let bounds_data = pk_trbfv::template::PkTrBfvBoundsData {
                eek_bound: bounds.eek_bound.to_string(),
                sk_bound: bounds.sk_bound.to_string(),
                r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
            };

            let pk_trbfv_template_params = PkTrBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(bfv_params.degree(), l, circuit_type),
                &bounds_data,
            )?;

            let template_generator = PkTrBfvMainTemplate;
            template_generator.generate_main_file(&pk_trbfv_template_params, output_dir)?;
        }
        "dec-share-trbfv" => {
            use dec_share_trbfv::bounds::DecShareTrBfvBounds;
            use dec_share_trbfv::template::{
                DecShareTrBfvMainTemplate, DecShareTrBfvTemplateParams,
            };

            let (_, bounds) = DecShareTrBfvBounds::compute(bfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute Greco bounds: {e:?}"))?;

            let bounds_data = dec_share_trbfv::template::DecShareTrBfvBoundsData {
                decryption_share_bound: bounds.decryption_share_bound.to_string(),
                r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
            };

            let dec_share_trbfv_template_params = DecShareTrBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(bfv_params.degree(), l, circuit_type),
                &bounds_data,
            )?;

            let template_generator = DecShareTrBfvMainTemplate;
            template_generator.generate_main_file(&dec_share_trbfv_template_params, output_dir)?;
        }
        _ => {
            anyhow::bail!("No main template generator available for circuit: {circuit_type}");
        }
    }

    Ok(())
}

/// Main entry point for the CLI application
///
/// This function parses command-line arguments and executes the appropriate
/// command. It provides a clean, user-friendly interface with progress
/// indicators and helpful error messages.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("🚀 zkFHE Generator");
    println!("Generating cryptographic parameters...\n");

    match cli.command {
        Commands::Generate {
            circuit,
            preset,
            bfv: _bfv,
            parameter_type,
            verbose,
            output,
            main,
            sample_type,
        } => {
            // Ensure output directory exists
            std::fs::create_dir_all(&output)?;

            // Parse parameter type
            let param_type = ParameterType::from_str_to_parameter_type(&parameter_type)?;

            // Parse sample type (only used for greco circuit with BFV)
            let effective_sample_type = if circuit.to_lowercase() == "greco"
                && param_type == ParameterType::Bfv
            {
                let parsed_type = SampleType::from_str_to_sample_type(&sample_type)?;
                // Print the sample type being used
                if sample_type == "secret-key" {
                    println!("📋 Using sample type: secret-key (default)");
                } else {
                    println!("📋 Using sample type: {}", parsed_type.as_str());
                }
                parsed_type
            } else {
                // Default to SecretKey for other circuits or parameter types
                // Warn if user specified a sample type for non-greco or non-BFV
                if circuit.to_lowercase() != "greco" {
                    eprintln!(
                        "⚠️  Warning: --sample-type is only applicable to the greco circuit. This flag will be ignored."
                    );
                } else if param_type != ParameterType::Bfv {
                    eprintln!(
                        "⚠️  Warning: --sample-type is only applicable to BFV parameter type. This flag will be ignored."
                    );
                }
                SampleType::SecretKey
            };

            generate_circuit_params(
                &circuit,
                preset.as_deref(),
                param_type,
                verbose,
                &output,
                main,
                effective_sample_type,
            )?;
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("📋 Available circuits:");
                println!("  • greco   - Greco circuit implementation (supports trbfv, bfv)");
                println!(
                    "  • pk-trbfv   - Public Key TRBFV circuit implementation (supports trbfv, bfv)"
                );
                println!(
                    "  • dec-share-trbfv   - Decryption Share TRBFV circuit implementation (supports trbfv)"
                );
            }
            if presets {
                println!("\n⚙️  Available presets:");
                println!(
                    "  • INSECURE_SET_2048_1032193_1   - Development (n=1, z=1000, λ=80, B=20)"
                );
                println!("  • INSECURE_SET_512_10_1   - Development (n=1, z=1000, λ=80, B=20)");
                println!("  • SET_8192_1000_4   - Development (n=1, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
                println!("\n🔧 Available parameter types:");
                println!("  • trbfv - Threshold BFV (stricter security, 40-61 bit primes)");
                println!("  • bfv   - Standard BFV (simpler conditions, 40-63 bit primes)");
                println!("\n🔐 Greco circuit:");
                println!("  • BFV parameter type: Encrypts threshold shares (Circuit 4)");
                println!("    - Default (--sample-type secret-key): Uses sk_sss share_row");
                println!("    - With --sample-type smudging-noise: Uses es_sss share_row");
                println!("  • trBFV parameter type: Encrypts messages/votes (Circuit 6)");
            }
            if !circuits && !presets {
                println!("📋 Available circuits:");
                println!("  • greco   - Greco circuit implementation (supports trbfv, bfv)");
                println!(
                    "  • pk-trbfv   - Public Key TRBFV circuit implementation (supports trbfv, bfv)"
                );
                println!("\n⚙️  Available presets:");
                println!(
                    "  • INSECURE_SET_2048_1032193_1   - Development (n=1, z=1000, λ=80, B=20)"
                );
                println!("  • INSECURE_SET_512_10_1   - Development (n=1, z=1000, λ=80, B=20)");
                println!("  • SET_8192_1000_4   - Development (n=1, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
                println!("\n🔧 Available parameter types:");
                println!("  • trbfv - Threshold BFV (stricter security, 40-61 bit primes)");
                println!("  • bfv   - Standard BFV (simpler conditions, 40-63 bit primes)");
                println!("\n💡 Use --parameter-type to choose between trbfv and bfv (required)");
                println!("   Example: --parameter-type trbfv");
                println!("\n🔐 Greco circuit usage:");
                println!("  • --parameter-type bfv: Encrypt threshold shares (Circuit 4)");
                println!("    - Default (--sample-type secret-key): Uses sk_sss share_row");
                println!("    - With --sample-type smudging-noise: Uses es_sss share_row");
                println!("  • --parameter-type trbfv: Encrypt messages/votes (Circuit 6)");
            }
        }
    }

    Ok(())
}
