//! PVW Parameter Search CLI
//!
//! Standalone command-line tool for searching PVW (Peikert-Vaikuntanathan-Waters) parameters
//! for zero-knowledge proofs using NTT-friendly primes.

use clap::Parser;
use num_bigint::BigUint;
use zkfhe_crypto_params::prime::PrimeItem;
use zkfhe_crypto_params::pvw::{PvwSearchConfig, pvw_search};
use zkfhe_crypto_params::utils::{approx_bits_from_log2, parse_hex_big};

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Search PVW params for zero-knowledge proofs with NTT-friendly CRT primes (40..63 bits)"
)]
struct Args {
    /// Number of parties n (e.g. ciphernodes, default is 1000)
    #[arg(long, default_value_t = 1000u128)]
    n: u128,

    /// Starting redundancy parameter ell (power of two, ≥ 2)
    #[arg(long, default_value_t = 2usize)]
    ell_start: usize,

    /// Maximum redundancy parameter ell (doubling schedule stops here)
    #[arg(long, default_value_t = 64usize)]
    ell_max: usize,

    /// Starting LWE dimension k (doubling schedule)
    #[arg(long, default_value_t = 256usize)]
    k_start: usize,

    /// Maximum LWE dimension k (inclusive, typically 32768)
    #[arg(long, default_value_t = 32768usize)]
    k_max: usize,

    /// Alpha parameter in Δ = floor(q_PVW^(α/ℓ))
    /// Common choices are 1 or 2, affecting the delta computation for noise analysis
    #[arg(long, default_value_t = 1u32)]
    delta_power_num: u32,

    /// Override BFV primes (comma-separated hex or decimal)
    /// If provided, these primes override the computed q_BFV modulus
    /// Example: "0x00800000022a0001,0x00800000021a0001"
    #[arg(long)]
    qbfv_primes: Option<String>,

    /// Limit for extra PVW prime enumeration beyond q_BFV
    /// Controls how many growth steps to attempt when expanding the modulus
    #[arg(long)]
    max_pvw_growth: Option<usize>,

    /// Verbose per-candidate logging
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

/// Parse comma-separated primes from string (hex or decimal)
fn parse_primes_from_string(primes_str: &str) -> Result<Vec<PrimeItem>, String> {
    let mut primes = Vec::new();

    for prime_str in primes_str.split(',') {
        let prime_str = prime_str.trim();
        if prime_str.is_empty() {
            continue;
        }

        let value = if prime_str.starts_with("0x") {
            parse_hex_big(prime_str)
        } else {
            BigUint::parse_bytes(prime_str.as_bytes(), 10)
                .ok_or_else(|| format!("Invalid decimal prime: {prime_str}"))?
        };

        let bitlen = value.bits() as u8;
        let log2 = zkfhe_crypto_params::utils::log2_big(&value);
        let hex = format!("0x{value:x}");

        primes.push(PrimeItem {
            bitlen,
            value,
            log2,
            hex,
        });
    }

    if primes.is_empty() {
        return Err("No valid primes found in input string".to_string());
    }

    Ok(primes)
}

fn main() {
    let args = Args::parse();

    println!("== PVW search with NTT-friendly primes (40..63 bits) ==");
    println!(
        "Inputs: n={}  ell_start={}  ell_max={}  k_start={}  k_max={}",
        args.n, args.ell_start, args.ell_max, args.k_start, args.k_max
    );
    println!("Parameters: delta_power_num={}", args.delta_power_num);
    println!(
        "Search schedule: ell doubling from {} to {}, k doubling from {} to {}",
        args.ell_start, args.ell_max, args.k_start, args.k_max
    );

    if let Some(ref primes_str) = args.qbfv_primes {
        println!("BFV primes override: {primes_str}");
    } else {
        println!("BFV primes: will be computed from default parameters");
    }

    if let Some(growth) = args.max_pvw_growth {
        println!("Max PVW growth: {growth}");
    } else {
        println!("Max PVW growth: default (4)");
    }
    println!();

    // Validate ell_start is a power of two and >= 2
    if !args.ell_start.is_power_of_two() || args.ell_start < 2 {
        eprintln!(
            "ERROR: ell_start must be a power of two and >= 2. Got {}",
            args.ell_start
        );
        std::process::exit(1);
    }

    // Validate ell_max >= ell_start
    if args.ell_max < args.ell_start {
        eprintln!(
            "ERROR: ell_max ({}) must be >= ell_start ({})",
            args.ell_max, args.ell_start
        );
        std::process::exit(1);
    }

    // Parse BFV primes if provided
    let bfv_primes = if let Some(ref primes_str) = args.qbfv_primes {
        match parse_primes_from_string(primes_str) {
            Ok(primes) => {
                println!("Parsed {} BFV primes from override string", primes.len());
                primes
            }
            Err(e) => {
                eprintln!("ERROR: Failed to parse BFV primes: {e}");
                std::process::exit(1);
            }
        }
    } else {
        // Use default BFV primes - we need to generate them
        // For now, we'll use a simple default set
        eprintln!("ERROR: BFV primes must be provided via --qbfv-primes for PVW search");
        eprintln!(
            "Example: --qbfv-primes \"36028797055270913,36028797054222337,36028797053698049,36028797051863041\""
        );
        std::process::exit(1);
    };

    let config = PvwSearchConfig {
        n: args.n,
        ell_start: args.ell_start,
        ell_max: args.ell_max,
        k_start: args.k_start,
        k_max: args.k_max,
        delta_power_num: args.delta_power_num,
        qbfv_primes: args.qbfv_primes.clone(),
        max_pvw_growth: args.max_pvw_growth,
        verbose: args.verbose,
    };

    // Search for PVW parameters
    match pvw_search(&config, &bfv_primes) {
        Ok(pvw) => {
            // Final summary of all parameters
            println!("\n=== PVW Result (summary dump) ===");
            println!("n (number of ciphernodes)                = {}", config.n);
            println!("ℓ (redundancy parameter)                 = {}", pvw.ell);
            println!("k (LWE dimension)                        = {}", pvw.k);
            println!(
                "α (delta power numerator)                = {}",
                config.delta_power_num
            );
            println!(
                "σ1 (sigma_e1)                            = {}",
                pvw.sigma1.to_str_radix(10)
            );
            println!(
                "σ2 (sigma_e2)                            = {}",
                pvw.sigma2.to_str_radix(10)
            );
            println!(
                "Δ (delta)                                = 2^{:.3}",
                pvw.delta_log2
            );
            println!(
                "|q_PVW|                                  ≈ {} bits",
                approx_bits_from_log2(pvw.q_pvw_bits as f64)
            );
            println!(
                "PVW primes used                          = {}",
                pvw.pvw_primes_used
            );
            println!(
                "Check: (ℓ-1)·log2(Δ)                     = {:.6}",
                pvw.lhs_log2
            );
            println!(
                "Check: log2(rhs)                         = {:.6}",
                pvw.rhs_log2
            );

            println!("\nPVW primes used (including BFV CRT primes):");
            for (i, p) in pvw.used_pvw_list.iter().enumerate() {
                println!(
                    "  {}: {}  (hex 0x{})  ({} bits)",
                    i + 1,
                    p,
                    p.to_str_radix(16),
                    p.bits()
                );
            }
        }
        Err(e) => {
            eprintln!("\nNo feasible PVW parameter set found across the specified search space.");
            eprintln!(
                "Try adjusting ell_start, ell_max, k_start, k_max, or providing different BFV primes."
            );
            eprintln!("❌ Error: {e}");
            std::process::exit(1);
        }
    }
}
