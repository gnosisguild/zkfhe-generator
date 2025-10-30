# Crypto Parameter Search Library

A Rust library for searching optimal BFV (Brakerski-Fan-Vercauteren) parameters using NTT-friendly primes. This library implements exact arithmetic for security analysis and parameter validation, specifically designed for applications requiring high security guarantees.

**Key Features:**
- **Exact Arithmetic**: BigUint-based calculations for precise security analysis  
- **NTT-Friendly Primes**: Uses 40-63 bit primes optimized for Number Theoretic Transform
- **Comprehensive Validation**: Multi-equation security constraint verification

The library implements the security analysis from:
- https://eprint.iacr.org/2024/1285.pdf (BFV security)

## BFV

Key security constraints validated:
- **Equation 1**: `2*(B_C + n*B_sm) < Δ` (decryption correctness)
- **Equation 2**: `2*d*n*B ≤ B_Enc * 2^{-λ}` (encryption noise bound)
- **Equation 3**: `B_C ≤ B_sm * 2^{-λ}` (ciphertext noise bound)
- **Equation 4**: `d ≥ 37.5*log2(q/B) + 75` (degree constraint)

### Parameters

- **n**: Number of parties (ciphernodes)
- **z**: Number of votes (also used as plaintext modulus k)
- **λ**: Statistical security parameter (negl(λ) = 2^{-λ})
- **B**: Bound on error distribution ψ
- **d**: LWE dimension (searched over powers of 2: 1024, 2048, 4096, 8192, 16384, 32768)

### Usage

To use as a CLI:

```bash
# Basic parameter search
cargo run --bin bfv-param-search

# With custom parameters
cargo run --bin bfv-param-search -- --n 1000 --z 1000 --lambda 80 --b 20 --verbose

# Help
cargo run --bin bfv-param-search -- --help
```

### Output

The search returns a `BfvSearchResult` containing:
- **d**: Chosen degree
- **q_bfv**: Ciphertext modulus (product of selected primes)
- **selected_primes**: NTT-friendly primes used
- **qi_values()**: Prime values as `Vec<u64>` for BFV parameter construction
- **Noise budgets**: B_Enc, B_fresh, B_C, B_sm
- **Validation logs**: Equation satisfaction details