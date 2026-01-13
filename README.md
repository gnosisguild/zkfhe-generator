# zkFHE TOML Generator

A modular Rust workspace for generating cryptographic parameters and TOML files for zkFHE (zero-knowledge Fully Homomorphic Encryption) circuits, specifically designed for Noir zero-knowledge proofs.

## Features

- **Modular Circuit Architecture**: Clean separation between shared utilities and circuit-specific implementations with a trait-based interface for easy extensibility
- **Pre-configured Parameter Sets**: Production-ready Enclave parameter sets (INSECURE_SET_512_10_1, SET_8192_1000_4, SET_8192_100_4) with comprehensive validation
- **Dual Parameter Types**: Support for both trBFV (threshold BFV, stricter security, 40-61 bit primes) and BFV (standard, simpler conditions, 40-63 bit primes)
- **Automated TOML Generation**: Generates Prover TOML files compatible with Noir circuits, including cryptographic parameters, bounds, and input vectors
- **Template Generation**: Creates template `main.nr` files with correct function signatures and parameter types for each circuit
- **Threshold Cryptography**: Configurable threshold parameters (num_parties, num_honest_parties, threshold) for circuits supporting distributed protocols

## Installation

### Prerequisites

- Rust 1.86+ (stable)
- Cargo

### Building

```bash
# Clone the repository
git clone <repository-url>
cd zkfhe-toml-generator

# Build all crates
cargo build

# Build specific crate
cargo build -p zkfhe-generator
```

## Quick Start

```bash
# List all available circuits
cargo run -p zkfhe-generator -- list --circuits

# List all available presets
cargo run -p zkfhe-generator -- list --presets

# Generate parameters for a circuit with preset
cargo run -p zkfhe-generator -- generate \
  --circuit greco \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./greco
```

## Available Circuits

The generator supports 8 circuits organized by their role in the threshold BFV protocol. The circuits are organized into 4 phases:

### Phase 0: BFV Key Setup

#### **Circuit 0: BFV Public Key Commitment (pk-bfv)**
Each party commits to their BFV public key during initial setup. This is used for encrypting secret shares in Phase 1.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit pk-bfv \
  --preset SET_8192_1000_4 \
  --parameter-type bfv \
  --main \
  --output ./circuit_0
```

**Supported Parameter Types:** BFV  
**Output:** `commit(pk_bfv)`

---

### Phase 1: Distributed Key Generation (DKG)

#### **Circuit 1: TRBFV Public Key Verification (pk-trbfv)**
Each party verifies the correctness of their TRBFV public key generation. Produces commitments to the secret key, public key, and smudging noise.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit pk-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./circuit_1
```

**Supported Parameter Types:** trBFV  
**Output:** `commit(sk_trbfv)`, `commit(pk_trbfv)`, `commit(e_sm)`

---

#### **Circuit 2: Verify Secret Key Shares (verify-shares-trbfv)**
Verifies the correctness of distributed secret key shares (sk_share) and smudging noise shares (e_sm_share) in threshold setup. Can be used for both types of shares by selecting the appropriate sample type.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit verify-shares-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --sample-type secret-key \
  --main \
  --output ./circuit_2
```

**Supported Parameter Types:** trBFV  
**Sample Types:** `secret-key`, `smudging-noise`  
**Configurable:** num_parties, threshold  
**Output:** `commit(sk_share[i][j])` or `commit(e_sm_share[i][j])`

---

#### **Circuit 3: Encrypt Threshold Shares (enc-bfv)**
Encrypts threshold secret key shares for distribution. During threshold setup, Party i encrypts shares for Party j using Party j's BFV public key. Used for both sk shares and e_sm shares.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit enc-bfv \
  --preset SET_8192_1000_4 \
  --parameter-type bfv \
  --main \
  --output ./circuit_3
```

**Supported Parameter Types:** BFV  
**Input:** `commit(pk_bfv)`, `commit(message)` where message is either `sk_share[i][j]` or `e_sm_share[i][j]`

---

#### **Circuit 4: BFV Decryption with Commitment Verification (dec-bfv)**
Proves correct BFV decryption of encrypted Shamir shares and verifies the commitment matches expected shares. Used to decrypt and aggregate both sk shares and e_sm shares.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit dec-bfv \
  --preset SET_8192_1000_4 \
  --parameter-type bfv \
  --sample-type secret-key \
  --main \
  --output ./circuit_4
```

**Supported Parameter Types:** BFV  
**Sample Types:** `secret-key`, `smudging-noise`  
**Configurable:** num_honest_parties  
**Output:** `commit(aggregated_sk_shares)` or `commit(aggregated_e_sm_shares)`

---

### Phase 2: Honest Party Aggregation

#### **Circuit 5: Public Key Aggregation (pk-agg-trbfv)**
Aggregates public keys from honest parties in the threshold setup to produce the final aggregated public key.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit pk-agg-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./circuit_5
```

**Supported Parameter Types:** trBFV  
**Configurable:** num_honest_parties  
**Input:** `commit(pk_trbfv)` from honest parties  
**Output:** `commit(pk0_agg, pk1_agg)`

---

### Phase 3: User Encryption

#### **Greco: Encrypt Messages/Votes (greco / enc-trbfv)**
Encrypts messages or votes in threshold voting systems using trBFV parameters. This is the main application-layer encryption circuit (e.g., for e-voting). Users encrypt their data with the aggregated public key.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit greco \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./greco
```

**Supported Parameter Types:** trBFV only  
**Input:** `pk_agg` from Circuit 5  
**Output:** Encrypted user data (ready for homomorphic computation)

**Note:** The circuit name `enc-trbfv` is an alias for `greco`. Both refer to the same circuit.

---

### Phase 4: Threshold Decryption

#### **Circuit 6: Decryption Share Generation (dec-share-trbfv)**
Proves correct decryption share computation in threshold BFV for a single party. Each honest party generates a decryption share using their aggregated secret shares.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit dec-share-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./circuit_6
```

**Supported Parameter Types:** trBFV  
**Configurable:** num_parties, threshold  
**Input:** `commit(s) == commit(aggregated_sk_shares)`, `commit(e) == commit(aggregated_e_sm_shares)`  
**Verification:** `d = c_0 + c_1 * s + e`  
**Output:** Decryption share `d` (public)

---

#### **Circuit 7: Decryption Share Aggregation (dec-share-agg-trbfv)**
Aggregates decryption shares from multiple parties using Lagrange interpolation, performs CRT reconstruction, and recovers the final decrypted plaintext message.

```bash
cargo run -p zkfhe-generator -- generate \
  --circuit dec-share-agg-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./circuit_7
```

**Supported Parameter Types:** trBFV  
**Configurable:** num_parties, threshold  
**Input:** Decryption shares `d` from Circuit 6  
**Output:** Final decrypted message

---


## Parameter Types

### trBFV (Threshold BFV)
- Stricter security constraints
- 40-61 bit primes
- Required for threshold cryptography circuits
- Used in circuits: 1, 2, 5, 6, 7 (greco)

### BFV (Standard BFV)
- Simpler security conditions
- 40-63 bit primes (including 62-bit primes)
- Used for non-threshold operations and share encryption
- Used in circuits: 0, 3, 4

## Available Presets

The generator supports several pre-configured Enclave parameter sets:

| Preset | Degree | Parties | Security | Description |
|--------|--------|---------|----------|-------------|
| **INSECURE_SET_512_10_1** | 512 | 1 | λ=40 | Fast development/testing with minimal security |
| **SET_8192_1000_4** | 8192 | 1000 | λ=128 | Production with 1000 parties (default) |
| **SET_8192_100_4** | 8192 | 100 | λ=128 | Production with 100 parties |

**Default:** If no preset is specified, `SET_8192_1000_4` is used.

```bash
# List all available presets with details
cargo run -p zkfhe-generator -- list --presets
```

## Threshold Cryptography Configuration

Many circuits support configurable threshold parameters for distributed protocols:

### Configuration Options

- `--num-parties` (N): Total number of parties in the threshold setup
- `--num-honest-parties` (H): Number of honest parties participating
- `--threshold` (T): Threshold value for reconstruction (must be T < N/2)

**Default Values:**
- `num_parties`: 5
- `num_honest_parties`: 3
- `threshold`: 2

### Examples

```bash
# Use default threshold values (backward compatible)
cargo run -p zkfhe-generator -- generate \
  --circuit dec-share-trbfv \
  --parameter-type trbfv

# Specify custom threshold configuration
cargo run -p zkfhe-generator -- generate \
  --circuit dec-share-agg-trbfv \
  --parameter-type trbfv \
  --num-parties 7 \
  --num-honest-parties 4 \
  --threshold 2

# Generate with custom configuration and template
cargo run -p zkfhe-generator -- generate \
  --circuit verify-shares-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --num-parties 5 \
  --threshold 2 \
  --main \
  --output ./circuit_3
```

### Circuits Supporting Threshold Configuration

| Circuit | Supported Parameters |
|---------|---------------------|
| **verify-shares-trbfv** (Circuit 2) | num_parties, threshold |
| **dec-bfv** (Circuit 4) | num_honest_parties |
| **pk-agg-trbfv** (Circuit 5) | num_honest_parties |
| **dec-share-trbfv** (Circuit 6) | num_parties, threshold |
| **dec-share-agg-trbfv** (Circuit 7) | num_parties, threshold |

## CLI Usage

### Generate Command

```bash
cargo run -p zkfhe-generator -- generate [OPTIONS]

Options:
  -c, --circuit <CIRCUIT>
          Circuit name to generate parameters for
          
  -p, --preset <PRESET>
          Preset configuration (INSECURE_SET_512_10_1, SET_8192_1000_4, SET_8192_100_4)
          
  -t, --parameter-type <PARAMETER_TYPE>
          Parameter type (trbfv or bfv) [required]
          
  -o, --output <OUTPUT>
          Output directory for generated files [default: .]
          
      --main
          Generate template main.nr file
          
      --sample-type <SAMPLE_TYPE>
          Sample type for share generation (dec-bfv and verify-shares-trbfv circuits)
          Options: secret-key, smudging-noise [default: secret-key]
          
      --num-parties <NUM_PARTIES>
          Number of parties (N)
          
      --num-honest-parties <NUM_HONEST_PARTIES>
          Number of honest parties (H)
          
      --threshold <THRESHOLD>
          Threshold (T) for reconstruction
          
  -v, --verbose
          Verbose output showing detailed parameter search process
          
      --bfv-n <N>
          Custom: Number of parties n (e.g. ciphernodes)
          
      --bfv-z <Z>
          Custom: Number of fresh ciphertext additions z
          
      --bfv-k <K>
          Custom: Plaintext modulus k
          
      --bfv-lambda <LAMBDA>
          Custom: Statistical Security parameter λ
          
      --bfv-b <B>
          Custom: Bound B on the error distribution
          
      --bfv-b-chi <B_CHI>
          Custom: Bound B_χ on the secret key distribution
```

### List Command

```bash
# List all available circuits
cargo run -p zkfhe-generator -- list --circuits

# List all available presets
cargo run -p zkfhe-generator -- list --presets

# List both circuits and presets
cargo run -p zkfhe-generator -- list
```

## Generated Output

The generator creates the following files in the output directory:

### 1. Prover.toml
Contains all parameters needed for the Noir prover:
- **Cryptographic Parameters**: BFV configuration (degree, moduli, plaintext modulus)
- **Bounds**: Valid ranges for polynomial coefficients based on security analysis
- **Input Vectors**: Sample input validation vectors for zero-knowledge proofs
- **Metadata**: Generation timestamp, configuration details, parameter compatibility

### 2. main.nr (Optional, with `--main` flag)
Template Noir circuit file with:
- Correct function signature for the circuit
- Parameterized types (N, L, etc.)
- Import statements for circuit-specific libraries
- Sample implementation structure

### 3. Config Files (e.g., trbfv.nr, bfv.nr)
Circuit-specific configuration files with:
- Global constants (N, L, QIS)
- Circuit-specific bounds arrays
- Pre-computed cryptographic parameters

## Advanced Usage Examples

### Custom BFV Parameters

```bash
# Generate with custom cryptographic parameters
cargo run -p zkfhe-generator -- generate \
  --circuit greco \
  --parameter-type trbfv \
  --bfv-n 2000 \
  --bfv-z 1000 \
  --bfv-k 1000 \
  --bfv-lambda 128 \
  --bfv-b 20 \
  --bfv-b-chi 1 \
  --verbose
```

### Verbose Output

```bash
# Show detailed parameter search and security analysis
cargo run -p zkfhe-generator -- generate \
  --circuit pk-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --verbose
```

### Complete Workflow Example

```bash
# Generate all threshold BFV protocol circuits for a 5-party system
mkdir -p ./threshold_circuits

# Phase 0: Circuit 0 - BFV Public Key Commitment
cargo run -p zkfhe-generator -- generate \
  --circuit pk-bfv \
  --preset SET_8192_1000_4 \
  --parameter-type bfv \
  --main \
  --output ./threshold_circuits/circuit_0

# Phase 1: Circuit 1 - TRBFV Public Key Verification
cargo run -p zkfhe-generator -- generate \
  --circuit pk-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./threshold_circuits/circuit_1

# Phase 1: Circuit 2 - Verify Shares
cargo run -p zkfhe-generator -- generate \
  --circuit verify-shares-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --sample-type secret-key \
  --num-parties 5 \
  --threshold 2 \
  --main \
  --output ./threshold_circuits/circuit_2

# Phase 1: Circuit 3 - Encrypt Shares
cargo run -p zkfhe-generator -- generate \
  --circuit enc-bfv \
  --preset SET_8192_1000_4 \
  --parameter-type bfv \
  --main \
  --output ./threshold_circuits/circuit_3

# Phase 1: Circuit 4 - BFV Decryption
cargo run -p zkfhe-generator -- generate \
  --circuit dec-bfv \
  --preset SET_8192_1000_4 \
  --parameter-type bfv \
  --sample-type secret-key \
  --num-honest-parties 3 \
  --main \
  --output ./threshold_circuits/circuit_4

# Phase 2: Circuit 5 - PK Aggregation
cargo run -p zkfhe-generator -- generate \
  --circuit pk-agg-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --num-honest-parties 3 \
  --main \
  --output ./threshold_circuits/circuit_5

# Phase 3: Greco - Encrypt Messages
cargo run -p zkfhe-generator -- generate \
  --circuit greco \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --main \
  --output ./threshold_circuits/greco

# Phase 4: Circuit 6 - Decryption Share
cargo run -p zkfhe-generator -- generate \
  --circuit dec-share-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --num-parties 5 \
  --threshold 2 \
  --main \
  --output ./threshold_circuits/circuit_6

# Phase 4: Circuit 7 - Decryption Share Aggregation
cargo run -p zkfhe-generator -- generate \
  --circuit dec-share-agg-trbfv \
  --preset SET_8192_1000_4 \
  --parameter-type trbfv \
  --num-parties 5 \
  --threshold 2 \
  --main \
  --output ./threshold_circuits/circuit_7
```

## Architecture

### Core Traits

#### Circuit Trait
The main trait that all circuit implementations must implement:

```rust
pub trait Circuit {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn parameter_type(&self) -> ParameterType;
    fn security_parameter(&self) -> usize;
    fn generate_toml(
        &self,
        trbfv_params: &Arc<BfvParameters>,
        bfv_params: &Arc<BfvParameters>,
        output_dir: &Path,
        ciphernodes_config: Option<&CiphernodesConfig>,
    ) -> Result<(), ZkFheError>;
}
```

#### TomlGenerator Trait
Trait for TOML file generation:

```rust
pub trait TomlGenerator {
    fn to_toml_string(&self) -> Result<String, Box<dyn Error>>;
    fn generate_toml(&self, output_dir: &Path) -> Result<PathBuf, Box<dyn Error>>;
}
```

#### MainTemplateGenerator Trait
Trait for main.nr template generation:

```rust
pub trait MainTemplateGenerator<T> {
    fn generate_template(&self, params: &T) -> ZkFheResult<String>;
    fn generate_main_file(&self, params: &T, output_dir: &Path) -> ZkFheResult<PathBuf>;
}
```

### Project Structure

```
zkfhe-toml-generator/
├── crates/
│   ├── generator/          # CLI application
│   ├── shared/             # Shared utilities and traits
│   ├── crypto_params/      # Cryptographic parameter search
│   ├── parity_matrix/      # Parity matrix utilities
│   └── circuits/           # Circuit implementations
│       ├── greco/          # Phase 3: Greco (user encryption)
│       ├── pk_bfv/         # Phase 0: Circuit 0 (BFV PK commitment)
│       ├── pk_trbfv/       # Phase 1: Circuit 1 (TRBFV PK verification)
│       ├── verify_shares_trbfv/  # Phase 1: Circuit 2 (verify shares)
│       ├── enc_bfv/        # Phase 1: Circuit 3 (encrypt shares)
│       ├── dec_bfv/        # Phase 1: Circuit 4 (decrypt shares)
│       ├── pk_agg_trbfv/   # Phase 2: Circuit 5 (PK aggregation)
│       ├── dec_share_trbfv/      # Phase 4: Circuit 6 (decryption share)
│       └── dec_share_agg_trbfv/  # Phase 4: Circuit 7 (decryption aggregation)
└── README.md
```

### Adding a New Circuit

1. Create a new crate in `crates/circuits/your-circuit/`
2. Implement the `Circuit` trait in `src/circuit.rs`
3. Add circuit-specific modules:
   - `bounds.rs`: Compute security bounds
   - `vectors.rs`: Generate input vectors
   - `toml.rs`: Implement `TomlGenerator`
   - `template.rs`: Implement `MainTemplateGenerator`
   - `configs.rs`: Generate config .nr files
   - `sample.rs`: Generate sample data
4. Register the circuit in `crates/generator/src/main.rs`:
   - Add to `get_circuit()` match statement
   - Add to `get_supported_parameter_types_per_circuit()`
   - Add to `generate_main_template()` match statement
5. Update workspace `Cargo.toml` to include new crate
6. Add tests in `src/` to ensure correctness

## Testing

```bash
# Run all tests
cargo test

# Run tests for specific crate
cargo test -p zkfhe-generator

# Run tests for specific circuit
cargo test -p zkfhe-greco

# Run with verbose output
cargo test -- --nocapture
```

## Circuit Reference Table

| Phase | Circuit # | Name | CLI Flag | Parameter Types | Threshold Config | Description |
|-------|-----------|------|----------|-----------------|------------------|-------------|
| 0 | 0 | BFV PK Commitment | `pk-bfv` | BFV | - | Commit to BFV public key |
| 1 | 1 | TRBFV PK Verification | `pk-trbfv` | trBFV | - | Verify TRBFV public key |
| 1 | 2 | Verify Shares | `verify-shares-trbfv` | trBFV | N, T | Verify sk/e_sm shares |
| 1 | 3 | Encrypt Shares | `enc-bfv` | BFV | - | Encrypt threshold shares |
| 1 | 4 | BFV Decryption | `dec-bfv` | BFV | H | Decrypt & verify shares |
| 2 | 5 | PK Aggregation | `pk-agg-trbfv` | trBFV | H | Aggregate public keys |
| 3 | - | User Encryption (Greco) | `greco` / `enc-trbfv` | trBFV | - | Encrypt votes/messages |
| 4 | 6 | Decryption Share | `dec-share-trbfv` | trBFV | N, T | Generate decryption share |
| 4 | 7 | Dec Share Aggregation | `dec-share-agg-trbfv` | trBFV | N, T | Aggregate & decrypt |

**Legend:** N = num_parties, H = num_honest_parties, T = threshold

## Contributing

Contributions are welcome! Please ensure:
- All tests pass (`cargo test`)
- Code follows Rust formatting (`cargo fmt`)
- Lints pass (`cargo clippy`)
- New circuits include comprehensive tests
- Documentation is updated

## License

This repository is licensed under the [LGPL-3.0+ license](LICENSE).

## Acknowledgments

Built by Gnosis Guild for the Enclave project, leveraging the [fhe.rs](https://github.com/gnosisguild/fhe.rs) library for BFV homomorphic encryption primitives.
