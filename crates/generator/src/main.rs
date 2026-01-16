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
use shared::circuit::{CiphernodesConfig, ParameterType, SampleType};
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

        /// Sample type for share_row generation (dec-bfv circuits only)
        ///
        /// This option is applicable to:
        /// - dec-bfv circuit
        ///
        /// Determines what type of share_row to generate:
        /// - `secret-key`: Generate sk_sss share_row (default)
        /// - `smudging-noise`: Generate es_sss share_row
        ///
        /// This affects the type of threshold share that gets encrypted/decrypted.
        /// Note: greco circuit only works with TRBFV and does not use sample_type.
        #[arg(long, default_value = "secret-key")]
        sample_type: String,

        /// Number of parties (N)
        ///
        /// Total number of parties in the threshold cryptography setup.
        /// If not specified, circuits will use their default values.
        #[arg(long)]
        num_parties: Option<usize>,

        /// Number of honest parties (H)
        ///
        /// Number of honest parties participating in the protocol.
        /// If not specified, circuits will use their default values.
        #[arg(long)]
        num_honest_parties: Option<usize>,

        /// Threshold (T)
        ///
        /// Threshold value for the threshold cryptography scheme.
        /// If not specified, circuits will use their default values.
        #[arg(long)]
        threshold: Option<usize>,
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
/// * `sample_type` - The sample type (only used for dec-bfv circuit)
/// * `lambda` - The security parameter (λ) to use for this circuit instance
///
/// # Returns
///
/// Returns a boxed circuit implementation or an error if the circuit is not found.
fn get_circuit(
    circuit_name: &str,
    parameter_type: ParameterType,
    sample_type: SampleType,
    lambda: usize,
) -> anyhow::Result<Box<dyn Circuit>> {
    match circuit_name.to_lowercase().as_str() {
        "enc-bfv" => {
            let circuit = enc_bfv::circuit::EncBfvCircuit::new(sample_type, lambda);
            Ok(Box::new(circuit))
        }
        "greco" => {
            // Greco only works with TRBFV
            if parameter_type != ParameterType::Trbfv {
                anyhow::bail!("Greco circuit only supports TRBFV parameter type");
            }
            let circuit = greco::circuit::GrecoCircuit::new(parameter_type, sample_type, lambda);
            Ok(Box::new(circuit))
        }
        "pk-trbfv" => {
            let circuit = pk_trbfv::circuit::PkTrBfvCircuit::new(parameter_type, lambda);
            Ok(Box::new(circuit))
        }
        "pk-bfv" => {
            let circuit = pk_bfv::circuit::PkBfvCircuit::new(parameter_type, lambda);
            Ok(Box::new(circuit))
        }
        "pk-agg-trbfv" => {
            let circuit = pk_agg_trbfv::circuit::PkAggTrBfvCircuit::new(parameter_type, lambda);
            Ok(Box::new(circuit))
        }
        "dec-share-trbfv" => {
            let circuit =
                dec_share_trbfv::circuit::DecShareTrBfvCircuit::new(parameter_type, lambda);
            Ok(Box::new(circuit))
        }
        "dec-share-agg-trbfv" => {
            let circuit =
                dec_share_agg_trbfv::circuit::DecShareAggTrBfvCircuit::new(parameter_type, lambda);
            Ok(Box::new(circuit))
        }
        "dec-bfv" => {
            let circuit = dec_bfv::circuit::DecBfvCircuit::new(sample_type, lambda);
            Ok(Box::new(circuit))
        }
        "verify-shares-trbfv" => {
            let circuit = verify_shares_trbfv::circuit::VerifySharesTrbfvCircuit::new(
                parameter_type,
                sample_type,
                lambda,
            );
            Ok(Box::new(circuit))
        }
        _ => anyhow::bail!("Unknown circuit: {circuit_name}"),
    }
}

/// Get supported parameter types per circuit.
pub fn get_supported_parameter_types_per_circuit(circuit_name: &str) -> Vec<ParameterType> {
    match circuit_name.to_lowercase().as_str() {
        "greco" => vec![ParameterType::Trbfv],
        "pk-trbfv" => vec![ParameterType::Trbfv],
        "pk-bfv" => vec![ParameterType::Bfv],
        "enc-bfv" => vec![ParameterType::Bfv],
        "pk-agg-trbfv" => vec![ParameterType::Trbfv],
        "dec-share-trbfv" => vec![ParameterType::Trbfv],
        "dec-share-agg-trbfv" => vec![ParameterType::Trbfv],
        "dec-bfv" => vec![ParameterType::Bfv],
        "verify-shares-trbfv" => vec![ParameterType::Trbfv],
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
        // degree: 512
        // plaintext_modulus: 10
        // moduli: [0xffffee001, 0xffffc4001]
        // paired with InsecureSet512_0xffffee001_1
        "INSECURE_SET_512_10_1" => BfvSearchConfig {
            // irrelevant since will be overridden by hardcoded values later in the code.
            n: 1,
            k: 1000,
            z: 1000,
            lambda: shared::DEFAULT_INSECURE_LAMBDA as u32,
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
            lambda: shared::DEFAULT_SECURE_LAMBDA as u32,
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
            lambda: shared::DEFAULT_SECURE_LAMBDA as u32,
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
#[allow(clippy::too_many_arguments)]
fn generate_circuit_params(
    circuit_name: &str,
    preset: Option<&str>,
    parameter_type: ParameterType,
    verbose: bool,
    output_dir: &Path,
    generate_main: bool,
    sample_type: SampleType,
    num_parties: Option<usize>,
    num_honest_parties: Option<usize>,
    threshold: Option<usize>,
) -> anyhow::Result<()> {
    if let Some(preset_name) = preset {
        println!("📋 Using preset: {preset_name}");
    }

    println!("📋 Using parameter type: {}", parameter_type.as_str());

    // Extract lambda (security parameter) - needed for circuit creation
    // For presets, determine lambda based on preset name.
    // For non-presets, create param_config early to get lambda (we'll reuse it later)
    let (lambda, param_config_opt) = if let Some(preset_name) = preset {
        // For hardcoded presets, determine lambda based on preset name
        // INSECURE presets typically use lower lambda, secure presets use DEFAULT_SECURE_LAMBDA
        let lambda = match preset_name {
            "INSECURE_SET_512_10_1" => shared::DEFAULT_INSECURE_LAMBDA, // Insecure presets
            _ => shared::DEFAULT_SECURE_LAMBDA, // Default secure for other presets
        };
        (lambda, None)
    } else {
        // For non-presets, create param_config to get lambda (we'll reuse it later)
        let param_config = create_bfv_config(preset, None, verbose)?;
        let lambda = param_config.lambda as usize;
        (lambda, Some(param_config))
    };

    println!(
        "🔐 Security parameter (λ): {} ({})",
        lambda,
        if lambda >= shared::DEFAULT_SECURE_LAMBDA {
            "secure"
        } else {
            "insecure"
        }
    );

    // Get circuit implementation with lambda
    let circuit = get_circuit(circuit_name, parameter_type, sample_type, lambda)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    if !is_compatible(circuit_name, &parameter_type) {
        anyhow::bail!("Parameter type is not compatible with circuit");
    }

    let (trbfv_params, bfv_params): (Arc<BfvParameters>, Arc<BfvParameters>) =
        if preset == Some("INSECURE_SET_512_10_1") {
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
                .set_variance(3)
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
            // Use param_config if we already created it, otherwise create it now
            let param_config = if let Some(config) = param_config_opt {
                config
            } else {
                create_bfv_config(preset, None, verbose)?
            };

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

    // Create ciphernodes config if provided
    let ciphernodes_config =
        if let (Some(np), Some(nhp), Some(t)) = (num_parties, num_honest_parties, threshold) {
            println!(
                "📋 Using ciphernodes config: num_parties={}, num_honest_parties={}, threshold={}",
                np, nhp, t
            );
            Some(CiphernodesConfig::new(np, nhp, t))
        } else {
            None // Use defaults in sample functions
        };

    // Generate TOML file
    println!("📄 Generating TOML file...");
    circuit
        .generate_toml(
            &trbfv_params,
            &bfv_params,
            output_dir,
            ciphernodes_config.as_ref(),
        )
        .map_err(|e| anyhow::anyhow!("Failed to generate TOML: {e}"))?;
    println!("✅ TOML file generated successfully");

    // Generate main.nr template if requested
    if generate_main {
        println!("📄 Generating main.nr template...");
        if circuit.parameter_type() == ParameterType::Trbfv {
            generate_main_template(
                circuit.as_ref(),
                &trbfv_params,
                &trbfv_params,
                output_dir,
                ciphernodes_config.as_ref(),
                sample_type,
            )?;
        } else {
            generate_main_template(
                circuit.as_ref(),
                &bfv_params,
                &trbfv_params,
                output_dir,
                ciphernodes_config.as_ref(),
                sample_type,
            )?;
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
    trbfv_params: &Arc<BfvParameters>,
    output_dir: &Path,
    ciphernodes_config: Option<&CiphernodesConfig>,
    sample_type: SampleType,
) -> anyhow::Result<()> {
    // Extract base parameters (N, L) that are common to all circuits
    let l = bfv_params.moduli().len();
    let circuit_type = circuit.name();

    // Generate circuit-specific template based on circuit type
    match circuit_type {
        "greco" => {
            use greco::bounds::GrecoBounds;
            use greco::configs::GrecoConfigsGenerator;
            use greco::template::{GrecoMainTemplate, GrecoTemplateParams};

            // Greco only works with TRBFV parameters
            let selected_params = trbfv_params;

            let (crypto_params, bounds) = GrecoBounds::compute(selected_params, 0)
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

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let greco_template_params = GrecoTemplateParams::from_bounds(
                BaseTemplateParams::new(selected_params.degree(), l, circuit_type),
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
            )?;

            // Generate config .nr file (named after parameter set: trbfv.nr or bfv.nr)
            let configs_filename = format!("{}.nr", circuit.parameter_type().as_str());
            GrecoConfigsGenerator::generate_configs_file(
                &crypto_params,
                &bounds,
                &greco_template_params,
                output_dir,
                &configs_filename,
                circuit.parameter_type().as_str(),
            )
            .map_err(|e| anyhow::anyhow!("Failed to generate greco configs file: {e:?}"))?;

            let template_generator = GrecoMainTemplate;
            template_generator.generate_main_file(&greco_template_params, output_dir)?;
        }
        "pk-trbfv" => {
            use pk_trbfv::bounds::PkTrBfvBounds;
            use pk_trbfv::template::{
                PkTrBfvBoundsData, PkTrBfvMainTemplate, PkTrBfvTemplateParams,
            };

            // pk-trbfv circuit now only supports TRBFV
            let selected_params = trbfv_params;

            let lambda = circuit.security_parameter();
            // Get ciphernodes config for smudging bound calculation
            let config = ciphernodes_config
                .cloned()
                .unwrap_or_else(CiphernodesConfig::defaults);
            // Needed for smudging bound calculation (B_c)
            // We set it to 1 as we only need one ciphertext for public key generation
            let num_ciphertexts = 1;

            let (_, bounds) =
                PkTrBfvBounds::compute(selected_params, 0, lambda, &config, num_ciphertexts)
                    .map_err(|e| anyhow::anyhow!("Failed to compute PkTrBfv bounds: {e:?}"))?;

            let bounds_data = PkTrBfvBoundsData {
                eek_bound: bounds.eek_bound.to_string(),
                sk_bound: bounds.sk_bound.to_string(),
                e_sm_bound: bounds.e_sm_bound.to_string(),
                r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
                pk_bound: bounds.pk_bound.to_string(),
            };

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let pk_trbfv_template_params = PkTrBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(
                    selected_params.degree(),
                    selected_params.moduli().len(),
                    circuit_type,
                ),
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
            )?;

            let template_generator = PkTrBfvMainTemplate;
            template_generator.generate_main_file(&pk_trbfv_template_params, output_dir)?;
        }
        "pk-bfv" => {
            use pk_bfv::bounds::PkBfvBounds;
            use pk_bfv::template::{PkBfvBoundsData, PkBfvMainTemplate, PkBfvTemplateParams};

            // pk-bfv circuit only supports BFV
            let selected_params = bfv_params;

            let (_, bounds) = PkBfvBounds::compute(selected_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute PkBfv bounds: {e:?}"))?;

            let bounds_data = PkBfvBoundsData {
                pk_bound: bounds.pk_bound.to_string(),
            };

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let pk_bfv_template_params = PkBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(
                    selected_params.degree(),
                    selected_params.moduli().len(),
                    circuit_type,
                ),
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
            )?;

            let template_generator = PkBfvMainTemplate;
            template_generator.generate_main_file(&pk_bfv_template_params, output_dir)?;
        }
        "pk-agg-trbfv" => {
            use pk_agg_trbfv::bounds::PkAggTrBfvCryptographicParameters;
            use pk_agg_trbfv::configs::PkAggTrBfvConfigsGenerator;
            use pk_agg_trbfv::template::{PkAggTrBfvMainTemplate, PkAggTrBfvTemplateParams};

            let crypto_params = PkAggTrBfvCryptographicParameters::compute(trbfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute pk-agg-trbfv bounds: {e:?}"))?;

            let num_honest_parties = ciphernodes_config
                .map(|c| c.num_honest_parties)
                .unwrap_or(CiphernodesConfig::defaults().num_honest_parties); // Default to 5 if not provided

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let pk_agg_trbfv_template_params = PkAggTrBfvTemplateParams::new(
                BaseTemplateParams::new(trbfv_params.degree(), l, circuit_type),
                num_honest_parties,
                crypto_params.pk_bound.to_string(),
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
            )?;

            // Generate config .nr file (named after parameter set: trbfv.nr)
            let configs_filename = format!("{}.nr", circuit.parameter_type().as_str());
            PkAggTrBfvConfigsGenerator::generate_configs_file(
                &crypto_params,
                &pk_agg_trbfv_template_params,
                output_dir,
                &configs_filename,
                circuit.parameter_type().as_str(),
            )
            .map_err(|e| anyhow::anyhow!("Failed to generate pk-agg-trbfv configs file: {e:?}"))?;

            let template_generator = PkAggTrBfvMainTemplate;
            template_generator.generate_main_file(&pk_agg_trbfv_template_params, output_dir)?;
        }
        "dec-share-trbfv" => {
            use dec_share_trbfv::bounds::DecShareTrBfvBounds;
            use dec_share_trbfv::configs::DecShareTrBfvConfigsGenerator;
            use dec_share_trbfv::template::{
                DecShareTrBfvMainTemplate, DecShareTrBfvTemplateParams,
            };

            let (crypto_params, bounds) = DecShareTrBfvBounds::compute(trbfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute dec-share-trbfv bounds: {e:?}"))?;

            let bounds_data = dec_share_trbfv::template::DecShareTrBfvBoundsData {
                decryption_share_bound: bounds.decryption_share_bound.to_string(),
                r1_bounds: bounds.r1_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
            };

            // Get num_parties and threshold from config or use defaults
            let config = ciphernodes_config
                .cloned()
                .unwrap_or_else(CiphernodesConfig::defaults);
            let num_parties = config.num_parties;
            let threshold = config.threshold;

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let dec_share_trbfv_template_params = DecShareTrBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(trbfv_params.degree(), l, circuit_type),
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
                num_parties as u32,
                threshold as u32,
            )?;

            // Generate config .nr file (named after parameter set: trbfv.nr)
            let configs_filename = format!("{}.nr", circuit.parameter_type().as_str());
            DecShareTrBfvConfigsGenerator::generate_configs_file(
                &crypto_params,
                &bounds,
                &dec_share_trbfv_template_params,
                output_dir,
                &configs_filename,
                circuit.parameter_type().as_str(),
            )
            .map_err(|e| {
                anyhow::anyhow!("Failed to generate dec-share-trbfv configs file: {e:?}")
            })?;

            let template_generator = DecShareTrBfvMainTemplate;
            template_generator.generate_main_file(&dec_share_trbfv_template_params, output_dir)?;
        }
        "dec-share-agg-trbfv" => {
            use dec_share_agg_trbfv::bounds::DecShareAggTrBfvBounds;
            use dec_share_agg_trbfv::configs::DecShareAggTrBfvConfigsGenerator;
            use dec_share_agg_trbfv::sample::generate_sample_decryption_share_aggregation;
            use dec_share_agg_trbfv::template::{
                DecShareAggTrBfvMainTemplate, DecShareAggTrBfvTemplateParams,
            };
            use dec_share_agg_trbfv::vectors::DecShareAggTrBfvVectors;

            let (crypto_params, bounds) = DecShareAggTrBfvBounds::compute(trbfv_params, 0)
                .map_err(|e| {
                    anyhow::anyhow!("Failed to compute dec-share-agg-trbfv bounds: {e:?}")
                })?;

            let bounds_data = dec_share_agg_trbfv::template::DecShareAggTrBfvBoundsData {
                delta: bounds.delta.to_string(),
                delta_half: bounds.delta_half.to_string(),
            };

            let config = ciphernodes_config
                .cloned()
                .unwrap_or_else(CiphernodesConfig::defaults);
            let threshold = config.threshold;
            let num_parties = config.num_parties;

            // Generate sample data to determine the trimmed degree
            let decryption_data = generate_sample_decryption_share_aggregation(
                trbfv_params,
                ciphernodes_config,
                circuit.security_parameter(),
            )
            .map_err(|e| anyhow::anyhow!("Failed to generate sample data: {e:?}"))?;

            let vectors = DecShareAggTrBfvVectors::compute(
                &decryption_data.d_share_polys,
                &decryption_data.party_ids,
                &decryption_data.message,
                trbfv_params,
                decryption_data.threshold,
                decryption_data.num_parties,
            )
            .map_err(|e| anyhow::anyhow!("Failed to compute vectors: {e:?}"))?;

            let vectors_standard = vectors.standard_form();

            let trimmed_degree = vectors_standard.count_nonzero_message_coefficients();

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let dec_share_agg_trbfv_template_params = DecShareAggTrBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(trimmed_degree, l, circuit_type),
                threshold as u32,
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
                num_parties as u32,
            )?;

            // Generate config .nr file (named after parameter set: trbfv.nr)
            let configs_filename = format!("{}.nr", circuit.parameter_type().as_str());
            DecShareAggTrBfvConfigsGenerator::generate_configs_file(
                &crypto_params,
                &dec_share_agg_trbfv_template_params,
                output_dir,
                &configs_filename,
                circuit.parameter_type().as_str(),
            )
            .map_err(|e| {
                anyhow::anyhow!("Failed to generate dec-share-agg-trbfv configs file: {e:?}")
            })?;

            let template_generator = DecShareAggTrBfvMainTemplate;
            template_generator
                .generate_main_file(&dec_share_agg_trbfv_template_params, output_dir)?;
        }
        "dec-bfv" => {
            use dec_bfv::template::{DecBfvMainTemplate, DecBfvTemplateParams};

            let num_honest_parties = ciphernodes_config
                .map(|c| c.num_honest_parties)
                .unwrap_or(CiphernodesConfig::defaults().num_honest_parties); // Default to 3 if not provided

            // Calculate bit_msg for commitment computation
            // Use a reasonable default based on plaintext modulus
            let plaintext_modulus = bfv_params.plaintext();
            let bit_msg = shared::template::calculate_bit_width(&plaintext_modulus.to_string())
                .map_err(|e| anyhow::anyhow!("Failed to calculate bit_msg: {e:?}"))?;

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            // Determine sample type postfix
            let sample_type_postfix = match sample_type {
                SampleType::SecretKey => "SK",
                SampleType::SmudgingNoise => "E_SM",
            };

            // For dec_bfv, L should be the number of TRBFV moduli (not BFV moduli)
            let l_trbfv = trbfv_params.moduli().len();

            let dec_bfv_template_params = DecBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(bfv_params.degree(), l_trbfv, circuit_type),
                num_honest_parties,
                bit_msg,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
                sample_type_postfix.to_string(),
            )?;

            let template_generator = DecBfvMainTemplate;
            template_generator.generate_main_file(&dec_bfv_template_params, output_dir)?;
        }
        "verify-shares-trbfv" => {
            use verify_shares_trbfv::bounds::VerifySharesTrbfvBounds;
            use verify_shares_trbfv::template::{
                VerifySharesTrbfvBoundsData, VerifySharesTrbfvMainTemplate,
                VerifySharesTrbfvTemplateParams,
            };

            let config = ciphernodes_config
                .cloned()
                .unwrap_or_else(|| CiphernodesConfig::new(5, 5, 2));

            // For verify_shares, we process shares for a single secret, so num_ciphertexts = 1
            let num_ciphertexts = 1;

            // Compute bounds based on sample type
            // For smudging noise, we need to compute the smudging bound
            let (crypto_params, bounds) = if matches!(sample_type, SampleType::SmudgingNoise) {
                VerifySharesTrbfvBounds::compute_with_smudging(
                    trbfv_params,
                    0,
                    circuit.security_parameter(),
                    &config,
                    num_ciphertexts,
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to compute verify_shares_trbfv bounds with smudging: {e:?}"
                    )
                })?
            } else {
                VerifySharesTrbfvBounds::compute(trbfv_params, 0).map_err(|e| {
                    anyhow::anyhow!("Failed to compute verify_shares_trbfv bounds: {e:?}")
                })?
            };

            // Use the actual secret bound for bit_secret calculation (smudging bound if available, otherwise sk_bound)
            let secret_bound_str = bounds
                .e_sm_bound
                .as_ref()
                .map(|b| b.to_string())
                .unwrap_or_else(|| bounds.sk_bound.to_string());

            let bounds_data = VerifySharesTrbfvBoundsData {
                sk_bound: bounds.sk_bound.to_string(),
                secret_bound: secret_bound_str,
                moduli: crypto_params.moduli,
            };

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            let mut sk_shares_template_params = VerifySharesTrbfvTemplateParams::from_bounds(
                BaseTemplateParams::new(trbfv_params.degree(), l, circuit_type),
                config.num_parties,
                config.threshold,
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
            )?;

            // Set the secret type postfix based on sample type
            sk_shares_template_params.secret_type_postfix = match sample_type {
                SampleType::SecretKey => "SK".to_string(),
                SampleType::SmudgingNoise => "E_SM".to_string(),
            };

            let template_generator = VerifySharesTrbfvMainTemplate;
            template_generator.generate_main_file(&sk_shares_template_params, output_dir)?;
        }
        "enc-bfv" => {
            use enc_bfv::bounds::EncBfvBounds;
            use enc_bfv::template::{EncBfvBoundsData, EncBfvMainTemplate, EncBfvTemplateParams};

            let (crypto_params, bounds) = EncBfvBounds::compute(bfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute enc_bfv bounds: {e:?}"))?;

            let bounds_data = EncBfvBoundsData {
                t: crypto_params.t.to_string(),
                q_mod_t: crypto_params.q_mod_t.to_string(),
                moduli: crypto_params.moduli,
                k0is: crypto_params.k0is,
                u_bound: bounds.u_bound.to_string(),
                e0_bound: bounds.e0_bound.to_string(),
                e1_bound: bounds.e1_bound.to_string(),
                msg_bound: bounds.msg_bound.to_string(),
                pk_bounds: bounds.pk_bounds.iter().map(|b| b.to_string()).collect(),
                r1_low_bounds: bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect(),
                r1_up_bounds: bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
                p1_bounds: bounds.p1_bounds.iter().map(|b| b.to_string()).collect(),
                p2_bounds: bounds.p2_bounds.iter().map(|b| b.to_string()).collect(),
            };

            // Determine security level based on lambda: "production" if lambda >= 80, "insecure" otherwise
            let security_level = if circuit.security_parameter() >= shared::DEFAULT_SECURE_LAMBDA {
                "production"
            } else {
                "insecure"
            };

            // Determine sample_type_postfix based on sample_type
            let sample_type_postfix = match sample_type {
                SampleType::SecretKey => "SK",
                SampleType::SmudgingNoise => "E_SM",
            };

            let enc_bfv_template_params = EncBfvTemplateParams::from_bounds(
                BaseTemplateParams::new(bfv_params.degree(), l, circuit_type),
                &bounds_data,
                circuit.parameter_type().as_str().to_string(),
                security_level.to_string(),
                sample_type_postfix.to_string(),
            )?;

            let template_generator = EncBfvMainTemplate;
            template_generator.generate_main_file(&enc_bfv_template_params, output_dir)?;
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
            num_parties,
            num_honest_parties,
            threshold,
        } => {
            // Ensure output directory exists
            std::fs::create_dir_all(&output)?;

            // Parse parameter type
            let param_type = ParameterType::from_str_to_parameter_type(&parameter_type)?;

            // Parse sample type (only used for dec-bfv, verify-shares-trbfv, and enc-bfv circuits)
            let effective_sample_type = {
                let circuit_name = circuit.to_lowercase();
                if circuit_name == "dec-bfv"
                    || circuit_name == "verify-shares-trbfv"
                    || circuit_name == "enc-bfv"
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
                    // Default to SecretKey for other circuits
                    // Warn if user specified a sample type for circuits that don't support it
                    if circuit_name == "greco" {
                        eprintln!(
                            "⚠️  Warning: --sample-type is not applicable to {} circuit (TRBFV only). This flag will be ignored.",
                            circuit_name
                        );
                    } else {
                        eprintln!(
                            "⚠️  Warning: --sample-type is only applicable to dec-bfv, verify-shares-trbfv, and enc-bfv circuits. This flag will be ignored."
                        );
                    }
                    SampleType::SecretKey
                }
            };

            generate_circuit_params(
                &circuit,
                preset.as_deref(),
                param_type,
                verbose,
                &output,
                main,
                effective_sample_type,
                num_parties,
                num_honest_parties,
                threshold,
            )?;
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("📋 Available circuits:");
                println!("  • greco       - Greco circuit implementation (TRBFV only)");
                println!(
                    "  • pk-trbfv     - Public Key Threshold BFV circuit implementation (supports trbfv)"
                );
                println!(
                    "  • pk-bfv       - Public Key BFV commitment circuit implementation (supports bfv)"
                );
                println!("  • enc-bfv     - Encryption BFV circuit implementation (supports bfv)");
                println!(
                    "  • pk-agg-trbfv   - Public Key Aggregation TRBFV circuit implementation (supports trbfv)"
                );
                println!(
                    "  • dec-share-trbfv   - Decryption Share TRBFV circuit implementation (supports trbfv)"
                );
                println!(
                    "  • dec-share-agg-trbfv   - Decryption Share Aggregation TRBFV circuit implementation (supports trbfv)"
                );
                println!("  • dec-bfv   - BFV Decryption circuit implementation (supports bfv)");
                println!(
                    "  • verify-shares-trbfv   - Secret Key Shares verification circuit (supports trbfv)"
                );
                println!("  • enc-bfv       - BFV Encryption circuit (supports bfv)");
            }
            if presets {
                println!("\n⚙️  Available presets:");
                println!("  • INSECURE_SET_512_10_1   - Development (n=1, z=1000, λ=80, B=20)");
                println!("  • SET_8192_1000_4   - Development (n=1, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
                println!("\n🔧 Available parameter types:");
                println!("  • trbfv - Threshold BFV (stricter security, 40-61 bit primes)");
                println!("  • bfv   - Standard BFV (simpler conditions, 40-63 bit primes)");
                println!("\n🔐 greco circuit:");
                println!("  • TRBFV parameter type only: Encrypts messages/votes (Circuit 7)");
            }
            if !circuits && !presets {
                println!("📋 Available circuits:");
                println!("  • greco       - Greco circuit implementation (TRBFV only)");
                println!(
                    "  • pk-trbfv     - Public Key Threshold BFV circuit implementation (supports trbfv)"
                );
                println!(
                    "  • pk-bfv       - Public Key BFV commitment circuit implementation (supports bfv)"
                );
                println!("  • enc-bfv     - Encryption BFV circuit implementation (supports bfv)");
                println!(
                    "  • pk-agg-trbfv   - Public Key Aggregation TRBFV circuit implementation (supports trbfv)"
                );
                println!(
                    "  • verify-shares-trbfv   - Secret Key Shares verification circuit (supports trbfv)"
                );
                println!("  • enc-bfv       - BFV Encryption circuit (supports bfv)");
                println!("\n⚙️  Available presets:");
                println!("  • INSECURE_SET_512_10_1   - Development (n=1, z=1000, λ=80, B=20)");
                println!("  • SET_8192_1000_4   - Development (n=1, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
                println!("\n🔧 Available parameter types:");
                println!("  • trbfv - Threshold BFV (stricter security, 40-61 bit primes)");
                println!("  • bfv   - Standard BFV (simpler conditions, 40-63 bit primes)");
                println!("\n💡 Use --parameter-type to choose between trbfv and bfv (required)");
                println!("   Example: --parameter-type trbfv");
                println!("\n🔐 greco circuit usage:");
                println!("  • --parameter-type trbfv: Encrypt messages/votes (Circuit 7)");
                println!("    Note: greco only supports TRBFV parameter type");
            }
        }
    }

    Ok(())
}
