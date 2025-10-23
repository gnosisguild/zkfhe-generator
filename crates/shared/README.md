This crate provides common functionality used across all zkFHE circuit implementations. It defines the core traits, configuration structures, and validation utilities that enable a modular approach to zkFHE circuit parameter generation.

The crate is organized into several modules:

- **`lib.rs`**: Main exports and validation module
- **`circuit.rs`**: Circuit traits, configuration structures, and parameter type definitions
- **`constants.rs`**: Cryptographic constants (ZKP modulus)
- **`template.rs`**: Main template generation traits and base parameters
- **`toml.rs`**: TOML generation traits
- **`utils.rs`**: Utility functions for string conversion and serialization

## Parameter Types

The crate supports flexible parameter type selection:

- **`ParameterType::Trbfv`**: Threshold BFV parameters with stricter security constraints (40-61 bit primes)
- **`ParameterType::Bfv`**: Standard BFV parameters with simpler conditions (40-63 bit primes including 62-bit primes)

This design allows circuits to support multiple parameter types while maintaining clean separation between parameter generation and circuit logic.