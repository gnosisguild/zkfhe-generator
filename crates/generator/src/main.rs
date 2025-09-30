//! zkFHE Generator CLI
//!
//! Command-line tool for generating zkFHE circuit parameters and TOML files.
//!
//! This binary provides a user-friendly interface for generating cryptographic
//! parameters and TOML files for zkFHE circuits. It supports multiple circuits
//! and preset configurations for different security levels.
//!
//! - **Circuit Registry**: Easy registration and management of circuit implementations
//! - **Preset System**: Pre-configured security levels (dev, test, prod)
//! - **Validation**: Comprehensive parameter validation and error handling
//! - **Beautiful Output**: Emoji-rich progress indicators and user feedback
use clap::{Args, Parser, Subcommand};
use std::path::{Path, PathBuf};

use crypto_params::bfv::{BfvSearchConfig, bfv_search};
use crypto_params::pvw::{PvwSearchConfig, pvw_search};
use crypto_params::utils::{
    approx_bits_from_log2, fmt_big_summary, log2_big, variance_uniform_sym_str_big,
    variance_uniform_sym_str_u128,
};
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
use num_bigint::BigInt;
use pvw::{PvwParameters, PvwParametersBuilder};
use shared::{BaseTemplateParams, Circuit, MainTemplateGenerator, SupportedParameterType};
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

        /// PVW-specific parameters (future)
        ///
        /// Use these flags to specify PVW parameters.
        /// This will be available in future versions.
        #[command(flatten)]
        pvw: Option<PvwParams>,

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
    bfv_n: Option<u128>,

    /// Number of fresh ciphertext additions z (number of votes)
    ///
    /// Note that the BFV plaintext modulus k will be defined as k = z.
    /// If not specified, uses the preset default or 1000.
    #[arg(long)]
    z: Option<u128>,

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
}

/// Propose PVW parameter sets, **starting with q_PVW = q_BFV**:
/// 1) Compute q_BFV from the provided CRT primes (default or override)
/// 2) First evaluate PVW with q_PVW = q_BFV (no extra primes)
/// 3) If needed, grow q_PVW by multiplying primes from a size-aware pool:
///      - target_bits = min bit-length among BFV CRT primes
///      - try more primes of bit-length == target_bits, then escalate to larger bit-lengths
#[derive(Args, Debug, Clone)]
pub struct PvwParams {
    /// Number of parties n (e.g. ciphernodes) - if not provided, uses BFV n value
    #[arg(long)]
    pvw_n: Option<usize>,

    /// Start ell (power of two, ≥ 2), where ell is the redundency parameter.
    #[arg(long)]
    ell_start: Option<usize>,

    /// Maximum ell (doubling schedule stops here)
    #[arg(long)]
    ell_max: Option<usize>,

    /// k start (doubling schedule), k here is the LWE dimension
    #[arg(long)]
    k_start: Option<usize>,

    /// k max (inclusive). Default = 32768
    #[arg(long)]
    k_max: Option<usize>,

    /// α in Δ = floor(q_PVW^(α/ℓ)). Common choices: 1 or 2
    #[arg(long)]
    delta_power_num: Option<u32>,

    /// Override q_BFV primes (comma-separated). Accepts hex (0x...) or decimal.
    /// Examples:
    ///   --qbfv-primes "0x00800000022a0001,0x00800000021a0001"
    ///   --qbfv-primes "562949951979521,562949951881217,562949951619073"
    #[arg(long)]
    qbfv_primes: Option<String>,

    /// Limit how many extra PVW primes to enumerate (growth steps) beyond the initial q_BFV.
    /// Default: 4 (tweak as needed).
    #[arg(long)]
    max_pvw_growth: Option<usize>,
}

/// Circuit registry - maps circuit names to their implementations
///
/// This function provides a centralized registry of all available circuit
/// implementations. To add a new circuit, simply add a new match arm here.
///
/// # Arguments
///
/// * `circuit_name` - The name of the circuit to load
///
/// # Returns
///
/// Returns a boxed circuit implementation or an error if the circuit is not found.
fn get_circuit(circuit_name: &str) -> anyhow::Result<Box<dyn Circuit>> {
    match circuit_name.to_lowercase().as_str() {
        "greco" => {
            let circuit = greco::circuit::GrecoCircuit;
            Ok(Box::new(circuit))
        }
        "pk_pvw" => {
            let circuit = pk_pvw::circuit::PkPvwCircuit;
            Ok(Box::new(circuit))
        }
        _ => anyhow::bail!("Unknown circuit: {circuit_name}"),
    }
}

/// Get BFV configuration based on preset
///
/// This function maps preset names to their corresponding BFV configurations.
/// Each preset provides different security levels and performance characteristics.
///
/// # Arguments
///
/// * `preset` - The preset name (dev, test, prod)
///
/// # Returns
///
/// Parameter configuration that can handle both BFV and PVW
#[derive(Debug, Clone)]
pub struct ParameterConfig {
    pub bfv_config: BfvSearchConfig,
    pub pvw_config: Option<PvwSearchConfig>,
}

impl ParameterConfig {
    /// Create parameter configuration from CLI arguments
    pub fn from_cli_args(
        preset: Option<&str>,
        bfv: Option<BfvParams>,
        pvw: Option<PvwParams>,
        verbose: bool,
    ) -> anyhow::Result<Self> {
        // Always create BFV config first (needed as base for PVW)
        let bfv_config = create_bfv_config(preset, bfv, verbose)?;

        // Create PVW config if PVW params provided OR if using a preset (presets include PVW defaults)
        let pvw_config = if pvw.is_some() || preset.is_some() {
            // Step 1: Create initial PVW config from preset + CLI args (like BFV)
            let mut pvw_config = create_pvw_config(preset, pvw, verbose)?;
            // Step 2: Update it with BFV computation results
            pvw_config = update_pvw_config_with_bfv(pvw_config, &bfv_config, verbose)?;
            Some(pvw_config)
        } else {
            None
        };

        Ok(ParameterConfig {
            bfv_config,
            pvw_config,
        })
    }
}

/// Create BFV search configuration from CLI arguments
fn create_bfv_config(
    preset: Option<&str>,
    bfv_params: Option<BfvParams>,
    verbose: bool,
) -> anyhow::Result<BfvSearchConfig> {
    // Start with preset defaults
    let mut config = match preset.unwrap_or("dev") {
        // TODO: there's currently no difference between dev and test.
        "dev" => BfvSearchConfig {
            n: 1,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        "test" => BfvSearchConfig {
            n: 1,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        "prod" => BfvSearchConfig {
            n: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        _ => anyhow::bail!("Unknown preset: {}", preset.unwrap()),
    };

    // Override with custom values if provided
    if let Some(bfv_params) = bfv_params {
        if let Some(n_val) = bfv_params.bfv_n {
            config.n = n_val;
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
    }

    Ok(config)
}

/// Create PVW search configuration from preset and CLI arguments (similar to BFV pattern)
fn create_pvw_config(
    preset: Option<&str>,
    pvw_params: Option<PvwParams>,
    verbose: bool,
) -> anyhow::Result<PvwSearchConfig> {
    // Start with preset defaults (similar to BFV)
    let mut config = match preset.unwrap_or("dev") {
        // TODO: there's currently no difference between dev and test.
        "dev" => PvwSearchConfig {
            n: 1,
            ell_start: 2,
            ell_max: 64,
            k_start: 1024,
            k_max: 32768,
            delta_power_num: 1,
            qbfv_primes: None,
            max_pvw_growth: None,
            verbose,
        },
        "test" => PvwSearchConfig {
            n: 1,
            ell_start: 2,
            ell_max: 64,
            k_start: 1024,
            k_max: 32768,
            delta_power_num: 1,
            qbfv_primes: None,
            max_pvw_growth: None,
            verbose,
        },
        "prod" => PvwSearchConfig {
            n: 1000,
            ell_start: 2,
            ell_max: 64,
            k_start: 1024,
            k_max: 32768,
            delta_power_num: 1,
            qbfv_primes: None,
            max_pvw_growth: None,
            verbose,
        },
        _ => anyhow::bail!("Unknown preset: {}", preset.unwrap()),
    };

    // Override with custom PVW values if provided
    if let Some(pvw_params) = pvw_params {
        if let Some(n_val) = pvw_params.pvw_n {
            config.n = n_val as u128;
        }
        if let Some(ell_start_val) = pvw_params.ell_start {
            config.ell_start = ell_start_val;
        }
        if let Some(ell_max_val) = pvw_params.ell_max {
            config.ell_max = ell_max_val;
        }
        if let Some(k_start_val) = pvw_params.k_start {
            config.k_start = k_start_val;
        }
        if let Some(k_max_val) = pvw_params.k_max {
            config.k_max = k_max_val;
        }
        if let Some(delta_power_num_val) = pvw_params.delta_power_num {
            config.delta_power_num = delta_power_num_val;
        }
        if let Some(qbfv_primes_val) = pvw_params.qbfv_primes {
            config.qbfv_primes = Some(qbfv_primes_val);
        }
        if let Some(max_pvw_growth_val) = pvw_params.max_pvw_growth {
            config.max_pvw_growth = Some(max_pvw_growth_val);
        }
    }

    Ok(config)
}

/// Update PVW config with BFV computation results
fn update_pvw_config_with_bfv(
    mut pvw_config: PvwSearchConfig,
    bfv_config: &BfvSearchConfig,
    verbose: bool,
) -> anyhow::Result<PvwSearchConfig> {
    // Run BFV search to get the modulus that PVW will start from
    println!("⚙️  Computing BFV parameters for PVW derivation...");
    let bfv_result = bfv_search(bfv_config)?;

    if verbose {
        println!("🔐 BFV Result for PVW: q_bfv={}", bfv_result.q_bfv);
    }

    // If no explicit qbfv_primes provided, use computed BFV modulus
    if pvw_config.qbfv_primes.is_none() {
        pvw_config.qbfv_primes = Some(bfv_result.q_bfv.to_string());
    }

    Ok(pvw_config)
}

/// Validate that the provided parameters are compatible with the circuit
fn validate_parameter_compatibility(
    circuit: &dyn Circuit,
    param_config: &ParameterConfig,
) -> anyhow::Result<()> {
    let supported_types = circuit.supported_parameter_types();
    let has_pvw = param_config.pvw_config.is_some();

    match supported_types {
        SupportedParameterType::Bfv => {
            if has_pvw {
                println!(
                    "⚠️  Warning: Circuit '{}' only supports BFV parameters, but PVW parameters were provided.",
                    circuit.name()
                );
                println!("   PVW parameters will be ignored for this circuit.");
                println!("   To suppress this warning, use only --bfv-* flags with this circuit.");
            }
        }
        SupportedParameterType::Pvw => {
            if !has_pvw {
                anyhow::bail!(
                    "Circuit '{}' requires PVW parameters, but none were provided. \
                     Please provide PVW parameters using --pvw-* flags.",
                    circuit.name()
                );
            }
        }
    }

    Ok(())
}

/// Generate parameters for a circuit
///
/// This function orchestrates the entire parameter generation process:
/// 1. Loads the specified circuit implementation
/// 2. Creates the BFV configuration from the preset
/// 3. Generates circuit parameters
/// 4. Creates the TOML file
///
/// # Arguments
///
/// * `circuit_name` - The name of the circuit to generate parameters for
/// * `preset` - The preset configuration to use
/// * `output_dir` - The directory where output files should be placed
///
/// # Returns
///
/// Returns `Ok(())` if generation was successful, or an error otherwise.
fn generate_circuit_params(
    circuit_name: &str,
    preset: Option<&str>,
    bfv: Option<BfvParams>,
    pvw: Option<PvwParams>,
    verbose: bool,
    output_dir: &Path,
    generate_main: bool,
) -> anyhow::Result<()> {
    println!("🔧 Generating parameters for circuit: {circuit_name}");

    // Create parameter configuration
    let param_config = ParameterConfig::from_cli_args(preset, bfv, pvw, verbose)?;

    if let Some(preset_name) = preset {
        println!("📋 Using preset: {preset_name}");
    }

    // Get circuit implementation
    let circuit = get_circuit(circuit_name)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    // Validate parameter compatibility
    validate_parameter_compatibility(circuit.as_ref(), &param_config)?;

    // Generate BFV parameters (always needed)
    println!(
        "🔐 BFV Parameters: n={}, z={}, λ={}, B={}",
        param_config.bfv_config.n,
        param_config.bfv_config.z,
        param_config.bfv_config.lambda,
        param_config.bfv_config.b
    );
    println!("⚙️  Searching for optimal BFV parameters...");

    let bfv_result = bfv_search(&param_config.bfv_config)?;

    // Decide distributions for B and B_chi per your rule:
    // CBD for B when Var_CBD = B/2 ≤ 16  <=>  B ≤ 32, otherwise Uniform over [-B..B]
    let (dist_b, var_b) = if param_config.bfv_config.b <= 32 {
        // CBD for small bounds
        let var = if param_config.bfv_config.b % 2 == 0 {
            (param_config.bfv_config.b / 2).to_string()
        } else {
            format!("{}/2", param_config.bfv_config.b)
        };
        ("CBD".to_string(), var)
    } else {
        // Uniform otherwise
        (
            "Uniform".to_string(),
            variance_uniform_sym_str_u128(param_config.bfv_config.b),
        )
    };

    // B_chi stays CBD with variance B_chi/2
    let (dist_b_chi, var_chi) = (
        "CBD".to_string(),
        if param_config.bfv_config.b_chi % 2 == 0 {
            (param_config.bfv_config.b_chi / 2).to_string()
        } else {
            format!("{}/2", param_config.bfv_config.b_chi)
        },
    );

    // BEnc is treated as uniform over [-BEnc..BEnc] for variance reporting
    let (dist_benc, var_benc) = (
        "Uniform".to_string(),
        variance_uniform_sym_str_big(&bfv_result.benc_min),
    );

    if verbose {
        println!("\n=== BFV Result (summary dump) ===");
        println!(
            "n (number of ciphernodes)                = {}",
            param_config.bfv_config.n
        );
        println!(
            "z (also k, that is, maximum number of votes, also plaintext space)            = {}",
            param_config.bfv_config.z
        );
        println!(
            "λ (Statistical security parameter)               = {}",
            param_config.bfv_config.lambda
        );
        println!(
            "B (bound on e1)     = {}   [Dist: {}, Var = {}]",
            param_config.bfv_config.b, dist_b, var_b
        );
        println!(
            "B_chi (bound on sk) = {}   [Dist: {}, Var = {}]",
            param_config.bfv_config.b_chi, dist_b_chi, var_chi
        );
        println!("d (LWE dimension)               f= {}", bfv_result.d);
        println!("k (plaintext)    = {}", bfv_result.k_plain_eff);
        println!("q_BFV (decimal)  = {}", bfv_result.q_bfv.to_str_radix(10));
        println!("|q_BFV|          = {}", fmt_big_summary(&bfv_result.q_bfv));
        println!("Δ (decimal)      = {}", bfv_result.delta.to_str_radix(10));
        println!("r_k(q)           = {}", bfv_result.rkq);
        println!(
            "BEnc (bound on e2)  = {}   [Dist: {}, Var = {}]",
            bfv_result.benc_min.to_str_radix(10),
            dist_benc,
            var_benc
        );
        println!("B_fresh          = {}", bfv_result.b_fresh.to_str_radix(10));
        println!("B_C              = {}", bfv_result.b_c.to_str_radix(10));
        println!("B_sm         = {}", bfv_result.b_sm_min.to_str_radix(10));
        println!("log2(LHS)        = {:.6}", bfv_result.lhs_log2);
        println!("log2(Δ)          = {:.6}", bfv_result.rhs_log2);
        println!(
            "q_i used ({}): {}",
            bfv_result.selected_primes.len(),
            bfv_result
                .selected_primes
                .iter()
                .map(|p| format!("{} ({} bits)", p.hex, p.bitlen))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Generate PVW parameters if requested
    let pvw_search_result = if let Some(pvw_config) = &param_config.pvw_config {
        println!(
            "🔐 PVW Parameters: n={}, ell_start={}, ell_max={}, k_start={}, k_max={}, delta_power_num={}",
            pvw_config.n,
            pvw_config.ell_start,
            pvw_config.ell_max,
            pvw_config.k_start,
            pvw_config.k_max,
            pvw_config.delta_power_num
        );
        println!("⚙️  PVW parameters computed using BFV result as starting point");

        println!("⚙️  Computing PVW parameters...");
        let pvw_result = pvw_search(pvw_config, &bfv_result.selected_primes)?;

        if verbose {
            println!("\n=== PVW Result (summary) ===");
            println!("ell (redundancy parameter)     = {}", pvw_result.ell);
            println!("k (LWE dimension)              = {}", pvw_result.k);
            println!("sigma_e1 (error bound 1)       = {}", pvw_result.sigma1);
            println!("sigma_e2 (error bound 2)       = {}", pvw_result.sigma2);
            println!(
                "delta_log2                     = {:.6}",
                pvw_result.delta_log2
            );
            println!("q_PVW bits                     = {}", pvw_result.q_pvw_bits);
            println!(
                "PVW primes used                = {}",
                pvw_result.pvw_primes_used
            );
            println!(
                "log2(LHS)                      = {:.6}",
                pvw_result.lhs_log2
            );
            println!(
                "log2(RHS)                      = {:.6}",
                pvw_result.rhs_log2
            );
            println!(
                "PVW primes used ({}): {}",
                pvw_result.used_pvw_list.len(),
                pvw_result
                    .used_pvw_list
                    .iter()
                    .map(|p| format!(
                        "0x{} ({} bits)",
                        p.to_str_radix(16),
                        approx_bits_from_log2(log2_big(p))
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        println!("✅ PVW parameters computed successfully");
        Some(pvw_result)
    } else {
        None
    };

    // Build BFV parameters for circuit use
    let bfv_params = BfvParametersBuilder::new()
        .set_degree(bfv_result.d as usize)
        .set_plaintext_modulus(bfv_result.k_plain_eff as u64)
        .set_moduli(bfv_result.qi_values().as_slice())
        .build_arc()
        .unwrap();

    println!(
        "🔐 BFV Configuration: degree={}, plaintext_modulus={}",
        bfv_params.degree(),
        bfv_params.plaintext()
    );

    // Build PVW parameters if PVW search was performed
    let pvw_params = if let Some(pvw_result) = &pvw_search_result {
        println!(
            "🔐 Building PVW parameters with {} moduli",
            bfv_result.qi_values().len()
        );

        // Build PVW parameters using the search results
        // tip: modify explicitly k or other parameters if needed for testing here.
        let pvw_params = PvwParametersBuilder::new()
            .set_parties(param_config.bfv_config.n as usize)
            .set_l(pvw_result.ell)
            .set_dimension(2)
            .set_moduli(bfv_result.qi_values().as_slice())
            .set_error_bound_1(BigInt::from(pvw_result.sigma1.clone()))
            .set_error_bound_2(BigInt::from(pvw_result.sigma2.clone()))
            .build_arc()
            .map_err(|e| anyhow::anyhow!("Failed to build PVW parameters: {e}"))?;

        println!("✅ PVW parameters built successfully");
        Some(pvw_params)
    } else {
        None
    };

    // Generate parameters
    println!("⚙️  Generating circuit parameters...");

    if let Some(pvw_params) = &pvw_params {
        circuit
            .generate_params(&bfv_params, Some(pvw_params))
            .map_err(|e| anyhow::anyhow!("Failed to generate parameters: {e}"))?;
    } else {
        circuit
            .generate_params(&bfv_params, None)
            .map_err(|e| anyhow::anyhow!("Failed to generate parameters: {e}"))?;
    }
    println!("✅ Parameters generated successfully");

    // Generate TOML file - circuits can access PVW data through the parameter config if needed
    println!("📄 Generating TOML file...");
    if let Some(pvw_params) = &pvw_params {
        circuit
            .generate_toml(&bfv_params, Some(pvw_params), output_dir)
            .map_err(|e| anyhow::anyhow!("Failed to generate TOML: {e}"))?;
    } else {
        circuit
            .generate_toml(&bfv_params, None, output_dir)
            .map_err(|e| anyhow::anyhow!("Failed to generate TOML: {e}"))?;
    }
    println!("✅ TOML file generated successfully");

    // Generate main.nr template if requested
    if generate_main {
        println!("📄 Generating main.nr template...");
        generate_main_template(
            circuit.as_ref(),
            &bfv_params,
            pvw_params.as_ref(),
            output_dir,
        )?;
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
///
/// # Arguments
///
/// * `circuit` - The circuit implementation
/// * `bfv_params` - The generated BFV parameters
/// * `pvw_params` - The generated PVW parameters (if any)
/// * `output_dir` - The directory where the main.nr file should be written
///
/// # Returns
///
/// Returns `Ok(())` if the template was generated successfully, or an error otherwise
fn generate_main_template(
    circuit: &dyn Circuit,
    bfv_params: &Arc<BfvParameters>,
    pvw_params: Option<&Arc<PvwParameters>>,
    output_dir: &Path,
) -> anyhow::Result<()> {
    // Extract base parameters (N, L) that are common to all circuits
    let n = bfv_params.degree();
    let l = bfv_params.moduli().len();
    let circuit_type = circuit.name();

    let base_params = BaseTemplateParams::new(n, l, circuit_type);

    // Generate circuit-specific template based on circuit type
    match circuit_type {
        "pk_pvw" => {
            // For PVW circuits, we need to extract K and N_PARTIES from PVW parameters
            let pvw = pvw_params
                .ok_or_else(|| anyhow::anyhow!("PVW parameters required for pk_pvw circuit"))?;

            // Import the PVW template generator
            use pk_pvw::template::{PkPvwMainTemplate, PvwTemplateParams};

            let pvw_template_params = PvwTemplateParams {
                base: base_params,
                k: pvw.k,
                n_parties: pvw.n,
            };

            let template_generator = PkPvwMainTemplate;
            template_generator.generate_main_file(&pvw_template_params, output_dir)?;
        }
        "greco" => {
            // For Greco circuits, we need to extract bounds from the circuit
            // We need to compute the bounds to get the bit widths
            use greco::bounds::GrecoBounds;

            // Compute bounds from BFV parameters
            let (_, bounds) = GrecoBounds::compute(bfv_params, 0)
                .map_err(|e| anyhow::anyhow!("Failed to compute Greco bounds: {e:?}"))?;

            // Convert bounds to strings for bit width calculation
            let bounds_data = greco::template::GrecoBoundsData {
                pk_bounds: bounds.pk_bounds.iter().map(|b| b.to_string()).collect(),
                ct_bounds: bounds.pk_bounds.iter().map(|b| b.to_string()).collect(), // Same as pk_bounds
                u_bound: bounds.u_bound.to_string(),
                e_bound: bounds.e_bound.to_string(),
                k1_low_bound: bounds.k1_low_bound.to_string(),
                k1_up_bound: bounds.k1_up_bound.to_string(),
                r1_low_bounds: bounds.r1_low_bounds.iter().map(|b| b.to_string()).collect(),
                r1_up_bounds: bounds.r1_up_bounds.iter().map(|b| b.to_string()).collect(),
                r2_bounds: bounds.r2_bounds.iter().map(|b| b.to_string()).collect(),
                p1_bounds: bounds.p1_bounds.iter().map(|b| b.to_string()).collect(),
                p2_bounds: bounds.p2_bounds.iter().map(|b| b.to_string()).collect(),
            };

            // Import the Greco template generator
            use greco::template::{GrecoMainTemplate, GrecoTemplateParams};

            let greco_template_params =
                GrecoTemplateParams::from_bounds(base_params, &bounds_data)?;

            let template_generator = GrecoMainTemplate;
            template_generator.generate_main_file(&greco_template_params, output_dir)?;
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
///
/// # Returns
///
/// Returns `Ok(())` if the command executed successfully, or an error otherwise.
fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    println!("🚀 zkFHE Generator");
    println!("Generating cryptographic parameters...\n");

    match cli.command {
        Commands::Generate {
            circuit,
            preset,
            bfv,
            pvw,
            verbose,
            output,
            main,
        } => {
            // Ensure output directory exists
            std::fs::create_dir_all(&output)?;

            generate_circuit_params(
                &circuit,
                preset.as_deref(),
                bfv,
                pvw,
                verbose,
                &output,
                main,
            )?;
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("📋 Available circuits:");
                println!("  • greco   - Greco circuit implementation (BFV only)");
                println!("  • pk_pvw  - PVW public key circuit (BFV + PVW parameters)");
            }
            if presets {
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
                println!("\n💡 PVW parameters can be specified with --pvw-* flags");
                println!("   Example: --pvw-n 1000 --ell-start 4 --secret-variance 0.5");
            }
            if !circuits && !presets {
                println!("📋 Available circuits:");
                println!("  • greco   - Greco circuit implementation (BFV only)");
                println!("  • pk_pvw  - PVW public key circuit (BFV + PVW parameters)");
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 128");
                println!("\n💡 PVW parameters can be specified with --pvw-* flags");
                println!("   Example: --pvw-n 1000 --ell-start 4 --secret-variance 0.5");
                println!("\n⚠️  Note: greco circuit only supports BFV parameters");
            }
        }
    }

    Ok(())
}
