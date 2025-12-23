/// Cryptographic parameters for PkAggTrBfv circuit
#[derive(Clone, Debug)]
pub struct PkAggTrBfvCryptographicParameters {
    pub moduli: Vec<u64>,
}

impl PkAggTrBfvCryptographicParameters {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "moduli": self.moduli
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_bounds_computation() {
        let params = test_parameters_trbfv();
        let crypto_params = PkAggTrBfvCryptographicParameters {
            moduli: params.moduli().to_vec(),
        };
        assert_eq!(crypto_params.moduli.len(), params.moduli().len());
    }
}
