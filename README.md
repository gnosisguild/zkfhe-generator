# zkFHE TOML Generator

A modular Rust workspace for generating cryptographic parameters and TOML files for zkFHE (zero-knowledge Fully Homomorphic Encryption) circuits, specifically designed for Noir zero-knowledge proofs.

- Clean separation between shared utilities and circuit-specific implementations in order to add new circuits with the trait-based interface.
- Pre-configured security levels (dev, test, prod) with comprehensive parameter validation and error handling.
- Generates Prover TOML files compatible with Noir circuits.
- Generates template `main.nr` files with correct function signatures and parameter types for each circuit.

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

## Usage

### CLI Commands

#### List available circuits and presets
```bash
cargo run -p zkfhe-generator -- list
```

#### Generate parameters for a specific circuit
```bash
# Basic generation with dev preset (defaults to BFV parameters)
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev

# Generate with trBFV parameters (threshold BFV, stricter security, 40-61 bit primes)
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type trbfv

# Generate with BFV parameters (simpler conditions, 40-63 bit primes)
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type bfv

# Generate with custom BFV parameters
cargo run -p zkfhe-generator -- generate --circuit greco --bfv-n 16384 --z 2000 --lambda 128

# Generate with custom output directory
cargo run -p zkfhe-generator -- generate --circuit greco --preset prod --output ./my-output

# Generate TOML + main.nr template
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --main
```

### PkTrBfv Circuit (Circuits 1 & 2 - Key Generation)

The `pktrbfv` circuit proves correct key generation for threshold BFV.

**Circuit 1: trBFV Key Generation**
```bash
cargo run -p zkfhe-generator -- generate --circuit pktrbfv --preset prod --parameter-type trbfv --main --output ./circuit_1
```

**Circuit 2: BFV Key Generation**
```bash
cargo run -p zkfhe-generator -- generate --circuit pktrbfv --preset prod --parameter-type bfv --main --output ./circuit_2
```

### Greco Circuit Usage

The Greco circuit proves correct BFV encryption operations. The type of encryption proven depends on the parameter type:

**Circuit 4 - BFV: Encrypt Threshold Shares**
```bash
# Encrypt threshold secret key shares for distribution
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type bfv --main --output ./circuit_4
```
Use case: During threshold setup, Party i encrypts shares for Party j using Party j's public key.

**Circuit 6 - trBFV: Encrypt Messages/Votes**
```bash
# Encrypt messages or votes in threshold voting system
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type trbfv --main --output ./circuit_6
```
Use case: Application layer encryption (e.g., e-voting with trBFV parameters).


### Generated Output

The generator creates a `Prover.toml` file containing the following. Please, note that these might vary a bit based on the circuit.

- **Cryptographic Parameters**: BFV configuration (degree, moduli, etc.)
- **Bounds**: Valid ranges for polynomial coefficients based on computed parameters
- **Vectors**: Input validation vectors for zero-knowledge proofs
- **Metadata**: Generation timestamp, configuration details, and parameter compatibility information

### Parameter Types and Circuit Compatibility

#### Parameter Types
- **trBFV**: Threshold BFV parameters with stricter security constraints (40-61 bit primes)
- **BFV**: Standard BFV parameters with simpler conditions (40-63 bit primes including 62-bit primes)

#### Current Circuit Support
- **greco**: Supports both trBFV and BFV parameter types
  - Proves correct BFV **encryption** operations
  - BFV parameter type: Encrypts threshold shares (Circuit 4)
  - trBFV parameter type: Encrypts messages/votes (Circuit 6)
  - Note: Circuit 5 (decryption proof) requires a custom circuit

- **pktrbfv**: Supports both trBFV and BFV parameter types
  - Proves correct **key generation**
  - Covers Circuits 1 and 2 from the threshold BFV protocol

## Architecture

### Core Traits

#### `Circuit`
The main trait that all circuit implementations must implement:

```rust
pub trait Circuit {
    fn name(&self) -> &'static str;
    fn description(&self) -> &'static str;
    fn generate_params(&self, config: &CircuitConfig) -> Result<CircuitParams, Box<dyn Error>>;
    fn generate_toml(&self, params: &CircuitParams, output_dir: &Path) -> Result<(), Box<dyn Error>>;
    fn validate_config(&self, config: &CircuitConfig) -> Result<(), Box<dyn Error>>;
}
```

#### `TomlGenerator`
Trait for TOML file generation:

```rust
pub trait TomlGenerator {
    fn to_toml_string(&self) -> Result<String, Box<dyn Error>>;
    fn generate_toml(&self, output_dir: &Path) -> Result<PathBuf, Box<dyn Error>>;
}
```

### Adding a New Circuit

1. Create a new crate in `crates/circuits/your-circuit/`
2. Implement the `Circuit` trait in `src/lib.rs`
3. Add circuit-specific modules (bounds, vectors, toml)
4. Register the circuit in the generator CLI
5. (optional) Add tests to ensure correctness

### Examples

#### Generate with different parameter types
```bash
# Generate with BFV parameters (threshold shares - Circuit 4)
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type bfv --verbose

# Generate with trBFV parameters (messages/votes - Circuit 6)
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type trbfv --verbose

# Generate with custom output and main.nr template for Circuit 4
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type bfv --output ./circuit_4 --main

# Generate with custom output and main.nr template for Circuit 6
cargo run -p zkfhe-generator -- generate --circuit greco --preset dev --parameter-type trbfv --output ./circuit_6 --main

# List available options
cargo run -p zkfhe-generator -- list
```

### Run all tests
```bash
cargo test
```

### Test CLI
```bash
cargo test -p zkfhe-generator
```

## 📄 License

This repo created under the [LGPL-3.0+ license](LICENSE).