/// Operation mode for Greco circuit
///
/// Greco proves correct BFV encryption operations.
/// The mode determines what type of sample data is generated and which phase
/// of the protocol is being proven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrecoMode {
    /// Encryption operation (sending phase)
    /// - BFV: Encrypt threshold shares for distribution (Circuit 4)
    /// - trBFV: Encrypt votes/messages (Circuit 6)
    Encryption,
    /// Decryption operation (receiving phase)
    /// - BFV: Prove aggregated share encryption (Circuit 5)
    /// - trBFV: NOT SUPPORTED (requires separate threshold decryption circuits)
    Decryption,
}

impl GrecoMode {
    /// Get the string representation of the mode
    pub fn as_str(&self) -> &'static str {
        match self {
            GrecoMode::Encryption => "encryption",
            GrecoMode::Decryption => "decryption",
        }
    }

    /// Parse mode from string
    pub fn from_str_to_mode(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "encryption" | "enc" => Ok(GrecoMode::Encryption),
            "decryption" | "dec" => Ok(GrecoMode::Decryption),
            _ => Err(format!(
                "Unknown Greco mode: {}. Supported modes: encryption, decryption (or enc, dec)",
                s
            )),
        }
    }

    /// Get the default mode
    pub fn default_mode() -> Self {
        GrecoMode::Encryption
    }
}
