//! BFV Parameter Search CLI
//!
//! Standalone command-line tool for searching BFV parameters using NTT-friendly primes.

use clap::Parser;
use shared::utils::{variance_uniform_sym_str_big, variance_uniform_sym_str_u128};
use zkfhe_crypto_params::bfv::{BfvSearchConfig, bfv_search, bfv_search_second_param};
use zkfhe_crypto_params::constants::K_MAX;
use zkfhe_crypto_params::utils::log2_big;
use zkfhe_crypto_params::utils::{approx_bits_from_log2, fmt_big_summary};

#[derive(Parser, Debug, Clone)]
#[command(
    version,
    about = "Search BFV params with NTT-friendly CRT primes (40..63 bits)"
)]
struct Args {
    /// Number of parties n (e.g. ciphernodes, default is 1000)
    #[arg(long, default_value_t = 1000u128)]
    n: u128,

    /// Number of fresh ciphertext z, i.e. number of votes. Note that the BFV plaintext modulus k will be defined as k = z
    #[arg(long, default_value_t = 1000u128)]
    z: u128,

    /// Plaintext modulus k (plaintext space).
    #[arg(long, default_value_t = 1000u128)]
    k: u128,

    /// Statistical Security parameter λ (negl(λ)=2^{-λ}).
    #[arg(long, default_value_t = 80u32)]
    lambda: u32,

    /// Bound B on the error distribution \psi (see pdf) used generate e1 when encrypting (e.g., 20 for CBD with σ≈3.2).
    #[arg(long, default_value_t = 20u128)]
    b: u128,

    /// Bound B_{\chi} on the distribution \chi (see pdf) used generate the secret key sk_i of each party i.
    /// By default, it is fixed to be 20 (that is the case when \chi is CBD with with σ≈3.2, which
    /// is the distribution by default in fhe.rs).
    #[arg(long, default_value_t = 1u128)]
    b_chi: u128,

    /// Verbose per-candidate logging
    #[arg(long, default_value_t = false)]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    if args.verbose {
        println!(
            "== BFV parameter search (NTT-friendly primes 40..61 bits; 62-bit and 63-bit are excluded) =="
        );
        println!(
            "Inputs: n={}  z={} k(user)={}  λ={}  B={} B_chi={}",
            args.n, args.z, args.k, args.lambda, args.b, args.b_chi
        );
        println!("Constraint: z ≤ k(effective) and z ≤ 2^25 (≈33.5M)\n");
    }

    // Enforce constraints on z and k
    if args.z == 0 {
        eprintln!("ERROR: z must be positive.");
        std::process::exit(1);
    }
    if args.z > K_MAX {
        eprintln!(
            "ERROR: too many votes — z = {} exceeds 2^25 = {}.",
            args.z, K_MAX
        );
        std::process::exit(1);
    }
    if args.k == 0 {
        eprintln!("ERROR: user-supplied plaintext space k must be positive.");
        std::process::exit(1);
    }

    let config = BfvSearchConfig {
        n: args.n,
        z: args.z,
        k: args.k,
        lambda: args.lambda,
        b: args.b,
        b_chi: args.b_chi,
        verbose: args.verbose,
    };

    // Search across all powers of two; stop at the first feasible candidate
    let Ok(bfv) = bfv_search(&config) else {
        eprintln!(
            "\nNo feasible BFV parameter set found across d∈{{256, 512, 1024,2048,4096,8192,16384,32768}}."
        );
        eprintln!("Try increasing d, or reducing n, z, λ, or B.");
        std::process::exit(1);
    };

    // Decide distributions for B and B_chi per your rule:
    // CBD for B when Var_CBD = B/2 ≤ 16  <=>  B ≤ 32, otherwise Uniform over [-B..B]
    let (dist_b, var_b) = if args.b <= 32 {
        // CBD for small bounds
        let var = if args.b % 2 == 0 {
            (args.b / 2).to_string()
        } else {
            format!("{}/2", args.b)
        };
        ("CBD".to_string(), var)
    } else {
        // Uniform otherwise
        ("Uniform".to_string(), variance_uniform_sym_str_u128(args.b))
    };

    // B_chi stays CBD with variance B_chi/2
    let (dist_b_chi, var_chi) = (
        "CBD".to_string(),
        if args.b_chi % 2 == 0 {
            (args.b_chi / 2).to_string()
        } else {
            format!("{}/2", args.b_chi)
        },
    );

    // BEnc is treated as uniform over [-BEnc..BEnc] for variance reporting
    let (dist_benc, var_benc) = (
        "Uniform".to_string(),
        variance_uniform_sym_str_big(&bfv.benc_min),
    );

    // ===== Second BFV parameter set (simpler conditions) =====
    let bfv2_opt = bfv_search_second_param(&config, &bfv);

    // ===== Final summary: both parameter sets =====
    println!("\n\n");
    println!("================================================================================");
    println!("                         FINAL BFV PARAMETER SETS");
    println!("================================================================================");

    println!("\n=== FIRST BFV PARAMETER SET ===");
    println!("n (number of ciphernodes)                = {}", config.n);
    println!("z (number of votes)                      = {}", config.z);
    println!(
        "k (plaintext space)                      = {} ({} bits)",
        bfv.k_plain_eff,
        approx_bits_from_log2((bfv.k_plain_eff as f64).log2())
    );
    println!(
        "λ (Statistical security parameter)       = {}",
        config.lambda
    );
    println!(
        "B (bound on e1)     = {}   [Dist: {}, Var = {}]",
        config.b, dist_b, var_b
    );
    println!(
        "B_chi (bound on sk) = {}   [Dist: {}, Var = {}]",
        config.b_chi, dist_b_chi, var_chi
    );
    println!("d (LWE dimension)               = {}", bfv.d);
    println!("q_BFV (decimal)  = {}", bfv.q_bfv.to_str_radix(10));
    println!("|q_BFV|          = {}", fmt_big_summary(&bfv.q_bfv));
    println!("Δ (decimal)      = {}", bfv.delta.to_str_radix(10));
    println!("r_k(q)           = {}", bfv.rkq);
    println!(
        "BEnc (bound on e2)  = {}   [Dist: {}, Var = {}]",
        bfv.benc_min.to_str_radix(10),
        dist_benc,
        var_benc
    );
    println!("B_fresh          = {}", bfv.b_fresh.to_str_radix(10));
    println!("B_C              = {}", bfv.b_c.to_str_radix(10));
    println!("B_sm         = {}", bfv.b_sm_min.to_str_radix(10));
    println!("log2(LHS)        = {:.6}", bfv.lhs_log2);
    println!("log2(Δ)          = {:.6}", bfv.rhs_log2);
    println!(
        "q_i used ({}): {}",
        bfv.selected_primes.len(),
        bfv.selected_primes
            .iter()
            .map(|p| format!("{} ({} bits)", p.hex, p.bitlen))
            .collect::<Vec<_>>()
            .join(", ")
    );

    if let Some(bfv2) = bfv2_opt {
        println!("\n=== SECOND BFV PARAMETER SET ===");
        println!(
            "k (plaintext space)                      = {} ({} bits)",
            bfv2.k_plain_eff,
            approx_bits_from_log2((bfv2.k_plain_eff as f64).log2())
        );
        println!(
            "λ (Statistical security parameter)       = {}",
            config.lambda
        );
        println!(
            "B (bound on e1)     = {}   [Dist: {}, Var = {}]",
            config.b, dist_b, var_b
        );
        println!(
            "B_chi (bound on sk) = {}   [Dist: {}, Var = {}]",
            config.b_chi, dist_b_chi, var_chi
        );
        println!("d (LWE dimension)               = {}", bfv2.d);
        println!("q_BFV (decimal)  = {}", bfv2.q_bfv.to_str_radix(10));
        println!("|q_BFV|          = {}", fmt_big_summary(&bfv2.q_bfv));
        println!("Δ (decimal)      = {}", bfv2.delta.to_str_radix(10));
        println!("r_k(q)           = {}", bfv2.rkq);
        println!(
            "BEnc (bound on e2, taken as B)  = {}   [Dist: {}, Var = {}]",
            config.b, dist_b, var_b
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
    } else {
        println!("\n=== SECOND BFV PARAMETER SET ===");
        println!("No second BFV parameter set found.");
    }

    println!("\n================================================================================");
}
