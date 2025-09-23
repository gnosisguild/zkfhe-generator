# Crypto Parameter Search Library

A Rust library for searching optimal BFV (Brakerski-Fan-Vercauteren) and PVW (Peikert–Vaikuntanathan–Waters) parameters using NTT-friendly primes. This library implements exact arithmetic for security analysis and parameter validation, specifically designed for applications requiring high security guarantees.

**Key Features:**
- **Dual Parameter Search**: Integrated BFV and PVW parameter generation
- **Exact Arithmetic**: BigUint-based calculations for precise security analysis  
- **NTT-Friendly Primes**: Uses 40-63 bit primes optimized for Number Theoretic Transform
- **Parameter Derivation**: PVW parameters derived from BFV computation results
- **Comprehensive Validation**: Multi-equation security constraint verification

The library implements the security analysis from:
- https://eprint.iacr.org/2024/1285.pdf (BFV security)
- https://eprint.iacr.org/2021/1397.pdf (PVW security)

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

## PVW

PVW parameters are used for zero-knowledge proof systems and are derived from BFV computation results.

### Key Security Constraints
- **Security**: `kℓ ≥ 37.5*log2(q_PVW/σ₁) + 7` (LWE security)
- **Flooding**: `σ₂ = ceil(√20973 * ℓ * √(k*n) * σ₁)` (noise flooding)  
- **Correctness**: `(ℓ-1)·log2(Δ) > log2(correctness_rhs)` (proof correctness)
- **Delta**: `Δ = floor(q_PVW^(α/ℓ))` with `gcd(Δ, q_PVW) = 1`

### Parameters

- **ℓ**: Redundancy parameter (power of 2, ≥ 2)
- **k**: LWE dimension (security parameter)
- **σ₁, σ₂**: Error bounds for proof system
- **α**: Alpha parameter in delta computation (typically 1 or 2)
- **q_PVW**: Modulus derived from BFV q_BFV with potential growth
