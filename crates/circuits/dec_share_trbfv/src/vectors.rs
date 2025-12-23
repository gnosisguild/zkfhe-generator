//! Input validation vectors for Decryption Share TRBFV zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct decryption share computation
//! in zero-knowledge for threshold BFV.

use bigint_poly::*;
use fhe::bfv::{BfvParameters, Ciphertext};
use fhe_math::rq::{Poly, Representation};
use itertools::izip;
use num_bigint::BigInt;
use num_traits::Zero;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use shared::commitments::compute_aggregated_commitment;
use shared::errors::ZkFheResult;
use shared::utils::to_string_2d_vec;
use std::sync::Arc;

/// Set of vectors for input validation of a decryption share
#[derive(Clone, Debug)]
pub struct DecShareTrBfvVectors {
    /// Ciphertext component c_0 for each CRT basis (public input)
    pub c_0is: Vec<Vec<BigInt>>,
    /// Ciphertext component c_1 for each CRT basis (public input)
    pub c_1is: Vec<Vec<BigInt>>,
    /// Aggregated sum of shares s for each CRT basis (secret witness)
    pub s_is: Vec<Vec<BigInt>>,
    /// Aggregated sum of noise e for each CRT basis (secret witness)
    pub e_is: Vec<Vec<BigInt>>,
    /// Quotient polynomials r_1 for each CRT basis (secret witness)
    pub r1is: Vec<Vec<BigInt>>,
    /// Quotient polynomials r_2 for each CRT basis (secret witness)
    pub r2is: Vec<Vec<BigInt>>,
    /// Computed decryption share d for each CRT basis (public output)
    pub d_is: Vec<Vec<BigInt>>,
    /// Expected commitment to aggregated shares s (from BFV decryption circuit)
    pub expected_s_commitment: BigInt,
    /// Expected commitment to aggregated noise e (from BFV decryption circuit)
    pub expected_e_commitment: BigInt,
}

impl DecShareTrBfvVectors {
    /// Create a new `DecShareTrBfvVectors` with the given number of moduli and degree.
    ///
    /// # Arguments
    ///
    /// * `num_moduli` - The number of moduli, which determines the number of inner vectors in 2D vectors.
    /// * `degree` - The size of each inner vector in the 2D vectors.
    ///
    /// # Returns
    ///
    /// Returns a new instance of `DecShareTrBfvVectors` with all fields initialized to zero.
    pub fn new(num_moduli: usize, degree: usize) -> Self {
        DecShareTrBfvVectors {
            c_0is: vec![vec![BigInt::zero(); degree]; num_moduli],
            c_1is: vec![vec![BigInt::zero(); degree]; num_moduli],
            s_is: vec![vec![BigInt::zero(); degree]; num_moduli],
            e_is: vec![vec![BigInt::zero(); degree]; num_moduli],
            r1is: vec![vec![BigInt::zero(); 2 * (degree - 1)]; num_moduli],
            r2is: vec![vec![BigInt::zero(); degree - 1]; num_moduli],
            d_is: vec![vec![BigInt::zero(); degree]; num_moduli],
            expected_s_commitment: BigInt::zero(),
            expected_e_commitment: BigInt::zero(),
        }
    }

    /// Create the centered validation vectors necessary for creating a decryption share correctness proof.
    ///
    /// Based on the lifted equation: d_j = c_0j + c_1j * s + e + r_2j * (X^N + 1) + r_1j * q_j (mod Z)
    ///
    /// # Arguments
    ///
    /// * `ct` - Ciphertext from fhe.rs.
    /// * `s_rns` - Aggregated sum of shares s = Σy_i (in RNS representation).
    /// * `e_rns` - Aggregated sum of noise e = Σe_i (in RNS representation).
    /// * `d_share_rns` - Computed decryption share d (in RNS representation).
    /// * `params` - BFV parameters.
    pub fn compute(
        ct: &Ciphertext,
        s_rns: &Poly,
        e_rns: &Poly,
        d_share_rns: &Poly,
        params: &Arc<BfvParameters>,
    ) -> ZkFheResult<DecShareTrBfvVectors> {
        let ctx = params.ctx_at_level(ct.level)?;
        let n: u64 = ctx.degree as u64;

        // Prepare RNS copies for extraction per modulus
        let mut s_rns_copy = s_rns.clone();
        let mut e_rns_copy = e_rns.clone();
        let mut d_rns_copy = d_share_rns.clone();

        s_rns_copy.change_representation(Representation::PowerBasis);
        e_rns_copy.change_representation(Representation::PowerBasis);
        d_rns_copy.change_representation(Representation::PowerBasis);

        // Extract and convert ciphertext polynomials
        let mut ct0 = ct.c[0].clone();
        let mut ct1 = ct.c[1].clone();
        ct0.change_representation(Representation::PowerBasis);
        ct1.change_representation(Representation::PowerBasis);

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64); // x^N term
        cyclo[n as usize] = BigInt::from(1u64); // x^0 term

        // Initialize matrices to store results
        let num_moduli = ctx.moduli().len();
        let mut res = DecShareTrBfvVectors::new(num_moduli, n as usize);

        let ct0_coeffs = ct0.coefficients();
        let ct1_coeffs = ct1.coefficients();
        let s_coeffs = s_rns_copy.coefficients();
        let e_coeffs = e_rns_copy.coefficients();
        let d_coeffs = d_rns_copy.coefficients();

        let ct0_coeffs_rows = ct0_coeffs.rows();
        let ct1_coeffs_rows = ct1_coeffs.rows();
        let s_coeffs_rows = s_coeffs.rows();
        let e_coeffs_rows = e_coeffs.rows();
        let d_coeffs_rows = d_coeffs.rows();

        // Perform the main computation logic
        let results: Vec<_> = izip!(
            ctx.moduli_operators(),
            ct0_coeffs_rows,
            ct1_coeffs_rows,
            s_coeffs_rows,
            e_coeffs_rows,
            d_coeffs_rows,
        )
        .enumerate()
        .par_bridge()
        .map(
            |(i, (qi, ct0_coeffs, ct1_coeffs, s_coeffs, e_coeffs, d_coeffs))| {
                let qi_bigint = BigInt::from(qi.modulus());

                // Convert to vectors of bigint, center, and reverse order.
                let mut c_0i: Vec<BigInt> =
                    ct0_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                let mut c_1i: Vec<BigInt> =
                    ct1_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                let mut s_i: Vec<BigInt> =
                    s_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                let mut e_i: Vec<BigInt> =
                    e_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                let mut d_i: Vec<BigInt> =
                    d_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();

                reduce_and_center_coefficients_mut(&mut c_0i, &qi_bigint);
                reduce_and_center_coefficients_mut(&mut c_1i, &qi_bigint);
                reduce_and_center_coefficients_mut(&mut s_i, &qi_bigint);
                reduce_and_center_coefficients_mut(&mut e_i, &qi_bigint);
                reduce_and_center_coefficients_mut(&mut d_i, &qi_bigint);

                // Compute d_i_hat = c_0i + c_1i * s_i + e_i
                // This is the expected value before lifting to Z
                let d_i_hat = {
                    let c_0i_poly = Polynomial::new(c_0i.clone());
                    let c_1i_poly = Polynomial::new(c_1i.clone());
                    let s_i_poly = Polynomial::new(s_i.clone());
                    let e_i_poly = Polynomial::new(e_i.clone());

                    // c_1i * s_i (degree 2*(n-1))
                    let c_1i_times_s_i = c_1i_poly.mul(&s_i_poly);
                    assert_eq!(
                        (c_1i_times_s_i.coefficients().len() as u64) - 1,
                        2 * (n - 1)
                    );

                    // c_0i + c_1i * s_i + e_i
                    c_0i_poly
                        .add(&c_1i_times_s_i)
                        .add(&e_i_poly)
                        .coefficients()
                        .to_vec()
                };
                assert_eq!((d_i_hat.len() as u64) - 1, 2 * (n - 1));

                // Check whether d_i_hat mod R_qi (the ring) is equal to d_i
                let mut d_i_hat_mod_rqi = d_i_hat.clone();
                reduce_in_ring(&mut d_i_hat_mod_rqi, &cyclo, &qi_bigint);
                assert_eq!(&d_i, &d_i_hat_mod_rqi);

                // Compute numerator = d_i - d_i_hat (in Z)
                // This should be divisible by (X^N + 1) and q_i
                let d_i_poly = Polynomial::new(d_i.clone());
                let d_i_hat_poly = Polynomial::new(d_i_hat.clone());
                let numerator = d_i_poly.sub(&d_i_hat_poly).coefficients().to_vec();
                assert_eq!((numerator.len() as u64) - 1, 2 * (n - 1));

                // First, compute r_2i = (d_i - d_i_hat) / (X^N + 1) mod Z_qi
                let mut numerator_mod_zqi = numerator.clone();
                reduce_and_center_coefficients_mut(&mut numerator_mod_zqi, &qi_bigint);

                let numerator_poly = Polynomial::new(numerator_mod_zqi.clone());
                let cyclo_poly = Polynomial::new(cyclo.clone());
                let (r2i_poly, r2i_rem_poly) = numerator_poly.div(&cyclo_poly).unwrap();
                let r2i = r2i_poly.coefficients().to_vec();
                let r2i_rem = r2i_rem_poly.coefficients().to_vec();
                assert!(r2i_rem.iter().all(|x| x.is_zero()));
                assert_eq!((r2i.len() as u64) - 1, n - 2); // Order(r2i) = N - 2

                // Verify: (d_i - d_i_hat) = (r2i * cyclo) mod Z_qi
                let r2i_poly_check = Polynomial::new(r2i.clone());
                let r2i_times_cyclo = r2i_poly_check.mul(&cyclo_poly).coefficients().to_vec();
                let mut r2i_times_cyclo_mod_zqi = r2i_times_cyclo.clone();
                reduce_and_center_coefficients_mut(&mut r2i_times_cyclo_mod_zqi, &qi_bigint);
                assert_eq!(&numerator_mod_zqi, &r2i_times_cyclo_mod_zqi);

                // Now compute r_1i = (d_i - d_i_hat - r2i * cyclo) / q_i mod Z_p
                let numerator_poly = Polynomial::new(numerator.clone());
                let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                let r1i_num = numerator_poly
                    .sub(&r2i_times_cyclo_poly)
                    .coefficients()
                    .to_vec();
                assert_eq!((r1i_num.len() as u64) - 1, 2 * (n - 1));

                let r1i_num_poly = Polynomial::new(r1i_num.clone());
                let qi_poly = Polynomial::new(vec![qi_bigint.clone()]);
                let (r1i_poly, r1i_rem_poly) = r1i_num_poly.div(&qi_poly).unwrap();
                let r1i = r1i_poly.coefficients().to_vec();
                let r1i_rem = r1i_rem_poly.coefficients().to_vec();
                assert!(r1i_rem.iter().all(|x| x.is_zero()));
                assert_eq!((r1i.len() as u64) - 1, 2 * (n - 1)); // Order(r1i) = 2*(N-1)

                // Verify: d_i = c_0i + c_1i * s_i + e_i + r2i * cyclo + r1i * q_i mod Z_p
                let r1i_poly = Polynomial::new(r1i.clone());
                let r1i_times_qi = r1i_poly.scalar_mul(&qi_bigint).coefficients().to_vec();
                let d_i_hat_poly = Polynomial::new(d_i_hat.clone());
                let r1i_times_qi_poly = Polynomial::new(r1i_times_qi.clone());
                let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                let mut d_i_calculated = d_i_hat_poly
                    .add(&r1i_times_qi_poly)
                    .add(&r2i_times_cyclo_poly)
                    .coefficients()
                    .to_vec();

                // Remove leading zeros
                while !d_i_calculated.is_empty() && d_i_calculated[0].is_zero() {
                    d_i_calculated.remove(0);
                }

                assert_eq!(&d_i, &d_i_calculated);

                (i, c_0i, c_1i, s_i, e_i, r1i, r2i, d_i)
            },
        )
        .collect();

        // Merge results into the `res` structure after parallel execution
        for (i, c_0i, c_1i, s_i, e_i, r1i, r2i, d_i) in results.into_iter() {
            res.c_0is[i] = c_0i;
            res.c_1is[i] = c_1i;
            res.s_is[i] = s_i;
            res.e_is[i] = e_i;
            res.r1is[i] = r1i;
            res.r2is[i] = r2i;
            res.d_is[i] = d_i;
        }

        // Compute commitments to s and e (matches circuit's compute_aggregated_commitment)
        res.expected_s_commitment = compute_aggregated_commitment(&res.s_is);
        res.expected_e_commitment = compute_aggregated_commitment(&res.e_is);

        Ok(res)
    }
}

impl DecShareTrBfvVectors {
    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();
        DecShareTrBfvVectors {
            c_0is: reduce_coefficients_2d(&self.c_0is, zkp_modulus),
            c_1is: reduce_coefficients_2d(&self.c_1is, zkp_modulus),
            s_is: reduce_coefficients_2d(&self.s_is, zkp_modulus),
            e_is: reduce_coefficients_2d(&self.e_is, zkp_modulus),
            r1is: reduce_coefficients_2d(&self.r1is, zkp_modulus),
            r2is: reduce_coefficients_2d(&self.r2is, zkp_modulus),
            d_is: reduce_coefficients_2d(&self.d_is, zkp_modulus),
            expected_s_commitment: {
                let mut reduced = self.expected_s_commitment.clone() % zkp_modulus;
                if reduced < BigInt::zero() {
                    reduced += zkp_modulus;
                }
                reduced
            },
            expected_e_commitment: {
                let mut reduced = self.expected_e_commitment.clone() % zkp_modulus;
                if reduced < BigInt::zero() {
                    reduced += zkp_modulus;
                }
                reduced
            },
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "c_0is": to_string_2d_vec(&self.c_0is),
            "c_1is": to_string_2d_vec(&self.c_1is),
            "s_is": to_string_2d_vec(&self.s_is),
            "e_is": to_string_2d_vec(&self.e_is),
            "r1is": to_string_2d_vec(&self.r1is),
            "r2is": to_string_2d_vec(&self.r2is),
            "d_is": to_string_2d_vec(&self.d_is),
            "expected_s_commitment": self.expected_s_commitment.to_string(),
            "expected_e_commitment": self.expected_e_commitment.to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_decryption_share;

    #[test]
    fn test_standard_form() {
        let vecs = DecShareTrBfvVectors::new(1, 512);
        let std_form = vecs.standard_form();

        // Check that all vectors are properly reduced
        let p = shared::constants::get_zkp_modulus();
        for vec_2d in &std_form.c_0is {
            assert!(vec_2d.iter().all(|x| x < &p));
        }
        for vec_2d in &std_form.c_1is {
            assert!(vec_2d.iter().all(|x| x < &p));
        }
        for vec_2d in &std_form.s_is {
            assert!(vec_2d.iter().all(|x| x < &p));
        }
        for vec_2d in &std_form.e_is {
            assert!(vec_2d.iter().all(|x| x < &p));
        }
    }

    #[test]
    fn test_vector_computation_to_json() {
        use shared::utils::test_parameters_trbfv;

        let params = test_parameters_trbfv();

        let decryption_data = generate_sample_decryption_share(
            &params,
            &params,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        // Compute vectors
        let vecs = DecShareTrBfvVectors::compute(
            &decryption_data.ciphertext,
            &decryption_data.s_rns,
            &decryption_data.e_rns,
            &decryption_data.d_share_rns,
            &params,
        )
        .unwrap();

        let json = vecs.to_json();

        // Check all required fields are present
        let required_fields = ["c_0is", "c_1is", "s_is", "e_is", "r1is", "r2is", "d_is"];

        for field in required_fields.iter() {
            assert!(json.get(field).is_some(), "Missing field: {}", field);
        }
    }
}
