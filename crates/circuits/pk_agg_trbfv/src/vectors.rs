use fhe::bfv::BfvParameters;
use fhe_math::rq::Representation;
use itertools::izip;
use num_bigint::BigInt;
use num_traits::Zero;
use shared::commitments::compute_threshold_pk_commitment;
use shared::errors::ZkFheResult;
use std::sync::Arc;

use crate::sample::PkAggTrBfvData;

/// Normalize a value to [0, q_i) range for use in reduce_mod
fn normalize_to_mod_range(val: BigInt, q: &BigInt) -> BigInt {
    let mut normalized = val % q;
    if normalized < BigInt::zero() {
        normalized += q;
    }
    normalized
}

/// Set of vectors for input validation of public key aggregation
#[derive(Clone, Debug)]
pub struct PkAggTrBfvVectors {
    /// Expected commitments to TRBFV public keys (from C1): one per honest party
    pub expected_pk_trbfv_commitments: Vec<BigInt>,
    /// Public key component 0 from honest parties: pk0[party_idx][basis_idx][coeff_idx]
    pub pk0: Vec<Vec<Vec<BigInt>>>,
    /// Public key component 1 from honest parties: pk1[party_idx][basis_idx][coeff_idx]
    /// Note: pk1 is the same (common random polynomial a) for all parties
    pub pk1: Vec<Vec<Vec<BigInt>>>,
    /// Aggregated public key component 0: pk0_agg[basis_idx][coeff_idx]
    pub pk0_agg: Vec<Vec<BigInt>>,
    /// Aggregated public key component 1: pk1_agg[basis_idx][coeff_idx]
    pub pk1_agg: Vec<Vec<BigInt>>,
}

impl PkAggTrBfvVectors {
    /// Create vectors from sample data
    pub fn compute(
        data: &PkAggTrBfvData,
        params: &Arc<BfvParameters>,
        bit_pk: u32,
    ) -> ZkFheResult<Self> {
        let ctx = params.ctx_at_level(0)?;

        // Extract pk0 and pk1 coefficients for each party and basis
        let mut pk0 = Vec::new();
        let mut pk1 = Vec::new();

        // For each honest party
        for party_idx in 0..data.num_honest_parties {
            let mut pk0_party = Vec::new();
            let mut pk1_party = Vec::new();

            // Extract pk0 and pk1 polynomials once per party
            let mut pk0_poly = data.pk0_shares[party_idx].clone();
            pk0_poly.change_representation(Representation::PowerBasis);
            let mut pk1_poly = data.a.clone();
            pk1_poly.change_representation(Representation::PowerBasis);

            // Get coefficient rows (one row per modulus)
            let pk0_coeffs = pk0_poly.coefficients();
            let pk1_coeffs = pk1_poly.coefficients();
            let pk0_coeffs_rows = pk0_coeffs.rows();
            let pk1_coeffs_rows = pk1_coeffs.rows();

            // For each CRT basis - use izip to iterate over moduli and coefficient rows together
            for (qi, pk0_coeffs_row, pk1_coeffs_row) in
                izip!(ctx.moduli_operators(), pk0_coeffs_rows, pk1_coeffs_rows)
            {
                let qi_bigint = BigInt::from(qi.modulus());

                // Convert to BigInt and reverse (circuit expects reversed order)
                // Keep in [0, q_i) range (do NOT center) to avoid overflow in reduce_mod
                let pk0_vec: Vec<BigInt> = pk0_coeffs_row
                    .iter()
                    .rev()
                    .map(|&x| normalize_to_mod_range(BigInt::from(x), &qi_bigint))
                    .collect();
                let pk1_vec: Vec<BigInt> = pk1_coeffs_row
                    .iter()
                    .rev()
                    .map(|&x| normalize_to_mod_range(BigInt::from(x), &qi_bigint))
                    .collect();

                pk0_party.push(pk0_vec);
                pk1_party.push(pk1_vec);
            }

            pk0.push(pk0_party);
            pk1.push(pk1_party);
        }

        // Extract pk0_agg and pk1_agg from aggregated public key
        // Note: Values must be in [0, q_i) range (not centered) to avoid overflow in reduce_mod
        let mut pk0_agg = Vec::new();
        let mut pk1_agg = Vec::new();

        // The aggregated public key has components [pk0, pk1]
        let mut pk0_agg_poly = data.public_key.c.c[0].clone();
        pk0_agg_poly.change_representation(Representation::PowerBasis);

        // pk1_agg should be sum_h(pk1[h]) = H * a (since all parties have the same a)
        // But the aggregated public key has pk1 = a, so we need to compute H * a manually
        let mut a_poly = data.a.clone();
        a_poly.change_representation(Representation::PowerBasis);

        // Get coefficient rows (one row per modulus)
        let pk0_coeffs = pk0_agg_poly.coefficients();
        let a_coeffs = a_poly.coefficients();
        let pk0_coeffs_rows = pk0_coeffs.rows();
        let a_coeffs_rows = a_coeffs.rows();

        let num_honest_parties = BigInt::from(data.num_honest_parties);

        // For each CRT basis - use izip to iterate over moduli and coefficient rows together
        for (qi, pk0_coeffs_row, a_coeffs_row) in
            izip!(ctx.moduli_operators(), pk0_coeffs_rows, a_coeffs_rows)
        {
            let qi_bigint = BigInt::from(qi.modulus());

            // Convert pk0_agg to BigInt and reverse
            // Keep in [0, q_i) range (do NOT center) to avoid overflow in reduce_mod
            let pk0_vec: Vec<BigInt> = pk0_coeffs_row
                .iter()
                .rev()
                .map(|&x| normalize_to_mod_range(BigInt::from(x), &qi_bigint))
                .collect();

            // Compute pk1_agg = H * a (sum of all pk1 shares)
            // Keep in [0, q_i) range (do NOT center) to avoid overflow in reduce_mod
            let pk1_vec: Vec<BigInt> = a_coeffs_row
                .iter()
                .rev()
                .map(|&x| normalize_to_mod_range(BigInt::from(x) * &num_honest_parties, &qi_bigint))
                .collect();

            pk0_agg.push(pk0_vec);
            pk1_agg.push(pk1_vec);
        }

        // Compute expected_pk_trbfv_commitments for each honest party
        // Each commitment is computed from pk0[i] and pk1[i] for party i
        let mut expected_pk_trbfv_commitments = Vec::new();
        for party_idx in 0..data.num_honest_parties {
            let commitment =
                compute_threshold_pk_commitment(&pk0[party_idx], &pk1[party_idx], bit_pk);
            expected_pk_trbfv_commitments.push(commitment);
        }

        Ok(PkAggTrBfvVectors {
            expected_pk_trbfv_commitments,
            pk0,
            pk1,
            pk0_agg,
            pk1_agg,
        })
    }

    /// Convert to standard form (reduce modulo ZKP modulus)
    pub fn standard_form(self) -> Self {
        use polynomial::reduce_coefficients_2d;
        use polynomial::reduce_coefficients_3d;
        use shared::constants::get_zkp_modulus;
        let zkp_modulus = get_zkp_modulus();

        // Reduce expected_pk_trbfv_commitments modulo ZKP modulus
        let expected_pk_trbfv_commitments: Vec<BigInt> = self
            .expected_pk_trbfv_commitments
            .into_iter()
            .map(|c| {
                let mut reduced = c % &zkp_modulus;
                if reduced < BigInt::zero() {
                    reduced += &zkp_modulus;
                }
                reduced
            })
            .collect();

        PkAggTrBfvVectors {
            expected_pk_trbfv_commitments,
            pk0: reduce_coefficients_3d(&self.pk0, &zkp_modulus),
            pk1: reduce_coefficients_3d(&self.pk1, &zkp_modulus),
            pk0_agg: reduce_coefficients_2d(&self.pk0_agg, &zkp_modulus),
            pk1_agg: reduce_coefficients_2d(&self.pk1_agg, &zkp_modulus),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_pk_aggregation;
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_vectors_computation() {
        use crate::bounds::PkAggTrBfvCryptographicParameters;
        let params = test_parameters_trbfv();
        let data = generate_sample_pk_aggregation(&params, None).unwrap();
        let crypto_params = PkAggTrBfvCryptographicParameters::compute(&params, 0).unwrap();
        let bit_pk =
            shared::template::calculate_bit_width(&crypto_params.pk_bound.to_string()).unwrap();
        let vectors = PkAggTrBfvVectors::compute(&data, &params, bit_pk).unwrap();

        assert_eq!(vectors.pk0.len(), data.num_honest_parties);
        assert_eq!(vectors.pk1.len(), data.num_honest_parties);
        assert_eq!(vectors.pk0_agg.len(), params.moduli().len());
        assert_eq!(vectors.pk1_agg.len(), params.moduli().len());
    }
}
