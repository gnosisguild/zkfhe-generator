This crate provides common functionality used across all zkFHE circuit implementations. It defines the core traits, configuration structures, and validation utilities that enable a modular approach to zkFHE circuit parameter generation.

The crate is organized into several modules:

- **`lib.rs`**: Main exports and validation module
- **`bfv.rs`**: BFV configuration and encryption helpers
- **`circuit.rs`**: Circuit traits and configuration structures
- **`constants.rs`**: Cryptographic constants (ZKP modulus)
- **`toml.rs`**: TOML generation traits
- **`utils.rs`**: Utility functions for string conversion and serialization