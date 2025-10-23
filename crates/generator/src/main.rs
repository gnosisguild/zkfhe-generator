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

use crypto_params::bfv::{BfvSearchConfig, bfv_search, bfv_search_second_param};
use crypto_params::utils::approx_bits_from_log2;
use crypto_params::utils::fmt_big_summary;
use crypto_params::utils::log2_big;
use fhe::bfv::{BfvParameters, BfvParametersBuilder};
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
/// Parameter configuration that can handle both BFV
#[derive(Debug, Clone)]
pub struct ParameterConfig {
    pub bfv_config: BfvSearchConfig,
}

impl ParameterConfig {
    /// Create parameter configuration from CLI arguments
    pub fn from_cli_args(
        preset: Option<&str>,
        bfv: Option<BfvParams>,
        verbose: bool,
    ) -> anyhow::Result<Self> {
        let bfv_config = create_bfv_config(preset, bfv, verbose)?;

        Ok(ParameterConfig { bfv_config })
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
            k: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        "test" => BfvSearchConfig {
            n: 1,
            k: 1000,
            z: 1000,
            lambda: 80,
            b: 20,
            b_chi: 1,
            verbose,
        },
        "prod" => BfvSearchConfig {
            n: 1000,
            k: 1000,
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
    verbose: bool,
    output_dir: &Path,
    generate_main: bool,
) -> anyhow::Result<()> {
    // Create parameter configuration
    let param_config = ParameterConfig::from_cli_args(preset, bfv, verbose)?;

    if let Some(preset_name) = preset {
        println!("📋 Using preset: {preset_name}");
    }

    // Get circuit implementation
    let circuit = get_circuit(circuit_name)?;
    println!("✅ Loaded circuit: {}", circuit.name());

    // Generate BFV parameters (always needed)
    println!(
        "🔐 BFV Configuration: n={}, z={}, k={}, λ={}, B={}, B_chi={}",
        param_config.bfv_config.n,
        param_config.bfv_config.z,
        param_config.bfv_config.k,
        param_config.bfv_config.lambda,
        param_config.bfv_config.b,
        param_config.bfv_config.b_chi
    );
    println!("⚙️  Searching for optimal BFV parameters...");

    let trbfv = bfv_search(&param_config.bfv_config)?;

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
        variance_uniform_sym_str_big(&trbfv.benc_min),
    );

    if verbose {
        println!("\n=== FIRST BFV PARAMETER SET ===");
        println!(
            "n (number of ciphernodes)                = {}",
            param_config.bfv_config.n
        );
        println!(
            "z (number of votes)                      = {}",
            param_config.bfv_config.z
        );
        println!(
            "k (plaintext space)                      = {} ({} bits)",
            trbfv.k_plain_eff,
            approx_bits_from_log2((trbfv.k_plain_eff as f64).log2())
        );
        println!(
            "λ (Statistical security parameter)       = {}",
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
        println!("d (LWE dimension)               = {}", trbfv.d);
        println!("q_BFV (decimal)  = {}", trbfv.q_bfv.to_str_radix(10));
        println!("|q_BFV|          = {}", fmt_big_summary(&trbfv.q_bfv));
        println!("Δ (decimal)      = {}", trbfv.delta.to_str_radix(10));
        println!("r_k(q)           = {}", trbfv.rkq);
        println!(
            "BEnc (bound on e2)  = {}   [Dist: {}, Var = {}]",
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

    let bfv2 = match bfv_search_second_param(&param_config.bfv_config, &trbfv) {
        Some(bfv2) => bfv2,
        None => anyhow::bail!("No second BFV parameter set found"),
    };

    if verbose {
        println!("\n=== SECOND BFV PARAMETER SET ===");
        println!(
            "k (plaintext space)                      = {} ({} bits)",
            bfv2.k_plain_eff,
            approx_bits_from_log2((bfv2.k_plain_eff as f64).log2())
        );
        println!(
            "λ (Statistical security parameter)       = {}",
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
        println!("d (LWE dimension)               = {}", bfv2.d);
        println!("q_BFV (decimal)  = {}", bfv2.q_bfv.to_str_radix(10));
        println!("|q_BFV|          = {}", fmt_big_summary(&bfv2.q_bfv));
        println!("Δ (decimal)      = {}", bfv2.delta.to_str_radix(10));
        println!("r_k(q)           = {}", bfv2.rkq);
        println!(
            "BEnc (bound on e2, taken as B)  = {}   [Dist: {}, Var = {}]",
            param_config.bfv_config.b, dist_b, var_b
        );
        println!("B_fresh          = {}", bfv2.b_fresh.to_str_radix(10));
        println!("B_C              = {}", bfv2.b_c.to_str_radix(10));
        println!("log2(2*B_C)      = {:.6}", log2_big(&(&bfv2.b_c << 1)));
        println!("log2(Δ)          = {:.6}", bfv2.rhs_log2);
        println!(
            "q_i used ({}): {}",
            bfv2.selected_primes.len(),
            bfv2.selected_primes
                .iter()
                .map(|p| format!("{} ({} bits)", p.hex, p.bitlen))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    // Build trBFV parameters for circuit use
    let trbfv_params = BfvParametersBuilder::new()
        .set_degree(trbfv.d as usize)
        .set_plaintext_modulus(trbfv.k_plain_eff as u64)
        .set_moduli(trbfv.qi_values().as_slice())
        .build_arc()
        .unwrap();

    println!(
        "🔐 trBFV Parameters: degree={}, plaintext_modulus={}, moduli=[{}]",
        trbfv_params.degree(),
        trbfv_params.plaintext(),
        trbfv_params
            .moduli()
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    // Build BFV parameters for circuit use
    let bfv_params = BfvParametersBuilder::new()
        .set_degree(bfv2.d as usize)
        .set_plaintext_modulus(bfv2.k_plain_eff as u64)
        .set_moduli(bfv2.qi_values().as_slice())
        .build_arc()
        .unwrap();

    println!(
        "🔐 BFV Parameters: degree={}, plaintext_modulus={}, moduli=[{}]",
        bfv_params.degree(),
        bfv_params.plaintext(),
        bfv_params
            .moduli()
            .iter()
            .map(|m| m.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    println!("✅ Parameters generated successfully");

    // Generate TOML file
    println!("📄 Generating TOML file...");
    circuit
        .generate_toml(&bfv_params, output_dir)
        .map_err(|e| anyhow::anyhow!("Failed to generate TOML: {e}"))?;
    println!("✅ TOML file generated successfully");

    // Generate main.nr template if requested
    if generate_main {
        println!("📄 Generating main.nr template...");
        generate_main_template(circuit.as_ref(), &bfv_params, output_dir)?;
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
/// * `output_dir` - The directory where the main.nr file should be written
///
/// # Returns
///
/// Returns `Ok(())` if the template was generated successfully, or an error otherwise
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

            let greco_template_params = GrecoTemplateParams::from_bounds(
                BaseTemplateParams::new(bfv_params.degree(), l, circuit_type),
                &bounds_data,
            )?;

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
            verbose,
            output,
            main,
        } => {
            // Ensure output directory exists
            std::fs::create_dir_all(&output)?;

            generate_circuit_params(&circuit, preset.as_deref(), bfv, verbose, &output, main)?;
        }
        Commands::List { circuits, presets } => {
            if circuits {
                println!("📋 Available circuits:");
                println!("  • greco   - Greco circuit implementation (BFV only)");
            }
            if presets {
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 80");
            }
            if !circuits && !presets {
                println!("📋 Available circuits:");
                println!("  • greco   - Greco circuit implementation (BFV only)");
                println!("\n⚙️  Available presets:");
                println!("  • dev   - Development (n=100, z=100, λ=40, B=20)");
                println!("  • test  - Testing (n=1000, z=1000, λ=80, B=20)");
                println!("  • prod  - Production (n=1000, z=1000, λ=80, B=20)");
                println!("\n💡 Custom BFV parameters can be specified with --bfv-* flags");
                println!("   Example: --bfv-n 2000 --bfv-lambda 128");
                println!("\n⚠️  Note: greco circuit only supports BFV parameters");
            }
        }
    }

    Ok(())
}
