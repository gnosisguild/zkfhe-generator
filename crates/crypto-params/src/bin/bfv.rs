//! BFV Parameter Search CLI
//!
//! Standalone command-line tool for searching BFV parameters using NTT-friendly primes.

use clap::Parser;
use zkfhe_crypto_params::bfv::{BfvSearchConfig, bfv_search};
use zkfhe_crypto_params::constants::K_MAX;
use zkfhe_crypto_params::utils::fmt_big_summary;

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

    println!("== BFV search with NTT-friendly primes (40..63 bits) ==");
    println!(
        "Inputs: n={}  z(k)={}  λ={}  B={} B_chi={}",
        args.n, args.z, args.lambda, args.b, args.b_chi
    );
    println!("Degree sweep: d = 1024, 2048, 4096, 8192, 16384, 32768");
    println!("Constraint: k := z and z ≤ 2^25 (≈33.5M)\n");

    // Enforce BFV k := z and k ≤ 2^25
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
    println!("Setting BFV plaintext modulus k := z = {}", args.z);

    let config = BfvSearchConfig {
        n: args.n,
        z: args.z,
        lambda: args.lambda,
        b: args.b,
        b_chi: args.b_chi,
        verbose: args.verbose,
    };

    // Search across all powers of two; stop at the first feasible candidate
    match bfv_search(&config) {
        Ok(bfv) => {
            // Final summary of all parameters
            println!("\n=== BFV Result (summary dump) ===");
            println!("n (number of ciphernodes)                = {}", config.n);
            println!(
                "z (also k, that is, maximum number of votes, also plaintext space)            = {}",
                config.z
            );
            println!(
                "λ (Statistical security parameter)               = {}",
                config.lambda
            );
            println!(
                "B (Bound on error distribution psi, the one used to genereate e1 when encrypting, also the same for the secret key)               = {}",
                config.b
            );
            println!("d (LWE dimension)               = {}", bfv.d);
            println!("k (plaintext)    = {}", bfv.k_plain_eff);
            println!("q_BFV (decimal)  = {}", bfv.q_bfv.to_str_radix(10));
            println!("|q_BFV|          = {}", fmt_big_summary(&bfv.q_bfv));
            println!("Δ (decimal)      = {}", bfv.delta.to_str_radix(10));
            println!("r_k(q)           = {}", bfv.rkq);
            println!(
                "BEnc (Bound on the encryption-noise distribution, the one used to generate e2) = {}",
                bfv.benc_min.to_str_radix(10)
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
        }
        Err(e) => {
            eprintln!(
                "\nNo feasible BFV parameter set found across d∈{{1024,2048,4096,8192,16384,32768}}."
            );
            eprintln!("Try increasing d, or reducing n, z, λ, or B.");
            eprintln!("❌ Error: {e}");
            std::process::exit(1);
        }
    }
}
