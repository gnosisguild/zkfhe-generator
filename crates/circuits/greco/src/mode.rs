/// Encryption mode for Greco circuit
///
/// Greco can prove correct encryption of different types of data.
/// This enum allows generating appropriate sample data for testing each use case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrecoMode {
    /// Encrypt arbitrary plaintexts (messages, votes, keys)
    /// Default mode for standard BFV encryption
    Key,
    /// Encrypt secret shares for threshold cryptography
    /// Used in threshold BFV setup phase where parties distribute shares
    Share,
}

impl GrecoMode {
    /// Get the string representation of the mode
    pub fn as_str(&self) -> &'static str {
        match self {
            GrecoMode::Key => "key",
            GrecoMode::Share => "share",
        }
    }

    /// Parse mode from string
    pub fn from_str_to_mode(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "key" => Ok(GrecoMode::Key),
            "share" => Ok(GrecoMode::Share),
            _ => Err(format!(
                "Unknown Greco mode: {}. Supported modes: key, share",
                s
            )),
        }
    }

    /// Get the default mode
    pub fn default_mode() -> Self {
        GrecoMode::Key
    }
}
