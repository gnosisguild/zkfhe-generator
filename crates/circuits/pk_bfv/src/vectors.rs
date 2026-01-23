use ::polynomial::*;
use fhe::bfv::BfvParameters;
use fhe::bfv::PublicKey;
use fhe_math::rq::Representation;
use itertools::izip;
use num_bigint::BigInt;
use rayon::prelude::*;
use serde_json::json;
use std::sync::Arc;

use shared::errors::ZkFheResult;
use shared::utils::to_string_2d_vec;

/// Set of vectors for BFV public key commitment circuit
#[derive(Clone, Debug)]
pub struct PkBfvVectors {
    pub pk0is: Vec<Vec<BigInt>>,
    pub pk1is: Vec<Vec<BigInt>>,
}

impl PkBfvVectors {
    pub fn new(num_moduli: usize, degree: usize) -> Self {
        PkBfvVectors {
            pk0is: vec![vec![BigInt::from(0); degree]; num_moduli],
            pk1is: vec![vec![BigInt::from(0); degree]; num_moduli],
        }
    }

    pub fn compute(
        public_key: &PublicKey,
        params: &Arc<BfvParameters>,
    ) -> ZkFheResult<PkBfvVectors> {
        let ctx = params.ctx_at_level(0)?;
        let num_moduli = ctx.moduli().len();

        // Extract public key components (pk0, pk1) from the ciphertext structure
        // public_key.c.c[0] is pk0, public_key.c.c[1] is pk1
        let mut pk0_copy = public_key.c.c[0].clone();
        let mut pk1_copy = public_key.c.c[1].clone();

        pk0_copy.change_representation(Representation::PowerBasis);
        pk1_copy.change_representation(Representation::PowerBasis);

        let pk0_coeffs = pk0_copy.coefficients();
        let pk1_coeffs = pk1_copy.coefficients();

        let pk0_coeffs_rows = pk0_coeffs.rows();
        let pk1_coeffs_rows = pk1_coeffs.rows();

        // Extract and convert public key polynomials per modulus
        let results: Vec<(usize, Vec<BigInt>, Vec<BigInt>)> =
            izip!(ctx.moduli_operators(), pk0_coeffs_rows, pk1_coeffs_rows)
                .enumerate()
                .par_bridge()
                .map(|(i, (qi, pk0_coeffs, pk1_coeffs))| {
                    let mut pk0i: Vec<BigInt> =
                        pk0_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                    let mut pk1i: Vec<BigInt> =
                        pk1_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();

                    let qi_bigint = BigInt::from(qi.modulus());

                    reduce_and_center_coefficients_mut(&mut pk0i, &qi_bigint);
                    reduce_and_center_coefficients_mut(&mut pk1i, &qi_bigint);

                    (i, pk0i, pk1i)
                })
                .collect();

        // Initialize result structure
        let mut res = PkBfvVectors::new(num_moduli, ctx.degree);

        // Merge results
        for (i, pk0i, pk1i) in results.into_iter() {
            res.pk0is[i] = pk0i;
            res.pk1is[i] = pk1i;
        }

        Ok(res)
    }

    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();
        PkBfvVectors {
            pk0is: reduce_coefficients_2d(&self.pk0is, zkp_modulus),
            pk1is: reduce_coefficients_2d(&self.pk1is, zkp_modulus),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "pk0is": to_string_2d_vec(&self.pk0is),
            "pk1is": to_string_2d_vec(&self.pk1is),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_encryption;
    use shared::utils::test_parameters_bfv;

    #[test]
    fn test_standard_form() {
        let vecs = PkBfvVectors::new(1, 512);
        let std_form = vecs.standard_form();

        // Check that all vectors are properly reduced
        let p = shared::constants::get_zkp_modulus();
        assert!(std_form.pk0is.iter().flatten().all(|x| x < &p));
        assert!(std_form.pk1is.iter().flatten().all(|x| x < &p));
    }

    #[test]
    fn test_vector_computation_to_json() {
        let params = test_parameters_bfv();
        let encryption_data = generate_sample_encryption(&params).unwrap();

        let vecs = PkBfvVectors::compute(&encryption_data.public_key, &params).unwrap();

        let json = vecs.to_json();

        // Check all required fields are present
        let required_fields = ["pk0is", "pk1is"];

        for field in required_fields.iter() {
            assert!(json.get(field).is_some(), "Missing field: {}", field);
        }
    }
}
