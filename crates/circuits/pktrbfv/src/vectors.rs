use bigint_poly::*;
use fhe::bfv::{BfvParameters, PublicKey};
use fhe_math::rq::{Poly, Representation};
use itertools::izip;
use num_bigint::BigInt;
use num_traits::Zero;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use std::sync::Arc;

use shared::errors::ZkFheResult;
use shared::utils::{
    reduce_coefficients, reduce_coefficients_2d, to_string_1d_vec, to_string_2d_vec,
};

/// Set of vectors for input validation of a ciphertext
#[derive(Clone, Debug)]
pub struct PkTrBfvVectors {
    pub a: Vec<Vec<BigInt>>,
    pub eek: Vec<BigInt>,
    pub sk: Vec<BigInt>,
    pub r1is: Vec<Vec<BigInt>>,
    pub r2is: Vec<Vec<BigInt>>,
    pub pk0is: Vec<Vec<BigInt>>,
    pub pk1is: Vec<Vec<BigInt>>,
}

impl PkTrBfvVectors {
    pub fn new(num_moduli: usize, degree: usize) -> Self {
        PkTrBfvVectors {
            a: vec![vec![BigInt::zero(); degree]; num_moduli],
            eek: vec![BigInt::zero(); degree],
            sk: vec![BigInt::zero(); degree],
            r1is: vec![vec![BigInt::zero(); 2 * (degree - 1)]; num_moduli],
            r2is: vec![vec![BigInt::zero(); degree - 1]; num_moduli],
            pk0is: vec![vec![BigInt::zero(); degree]; num_moduli],
            pk1is: vec![vec![BigInt::zero(); degree]; num_moduli],
        }
    }

    pub fn compute(
        a_rns: &Poly,
        eek_rns: &Poly,
        sk_rns: &Poly,
        pk: &PublicKey,
        params: &Arc<BfvParameters>,
    ) -> ZkFheResult<PkTrBfvVectors> {
        let ctx = params.ctx_at_level(0)?;
        let n: u64 = ctx.degree as u64;

        // Extract single vectors of a, eek, and sk as Vec<BigInt>, center and reverse
        let mut a_rns_copy = a_rns.clone();
        let mut eek_rns_copy = eek_rns.clone();
        let mut sk_rns_copy = sk_rns.clone();

        a_rns_copy.change_representation(Representation::PowerBasis);
        eek_rns_copy.change_representation(Representation::PowerBasis);
        sk_rns_copy.change_representation(Representation::PowerBasis);

        let a: Vec<BigInt> = unsafe {
            ctx.moduli_operators()[0]
                .center_vec_vt(
                    a_rns_copy
                        .coefficients()
                        .row(0)
                        .as_slice()
                        .ok_or_else(|| "Cannot center coefficients.".to_string())?,
                )
                .iter()
                .rev()
                .map(|&x| BigInt::from(x))
                .collect()
        };

        let eek: Vec<BigInt> = unsafe {
            ctx.moduli_operators()[0]
                .center_vec_vt(
                    eek_rns_copy
                        .coefficients()
                        .row(0)
                        .as_slice()
                        .ok_or_else(|| "Cannot center coefficients.".to_string())?,
                )
                .iter()
                .rev()
                .map(|&x| BigInt::from(x))
                .collect()
        };

        let sk: Vec<BigInt> = unsafe {
            ctx.moduli_operators()[0]
                .center_vec_vt(
                    sk_rns_copy
                        .coefficients()
                        .row(0)
                        .as_slice()
                        .ok_or_else(|| "Cannot center coefficients.".to_string())?,
                )
                .iter()
                .rev()
                .map(|&x| BigInt::from(x))
                .collect()
        };

        // Extract and convert public key polynomials
        let mut pk0: Poly = pk.c.c[0].clone();
        let mut pk1: Poly = pk.c.c[1].clone();
        pk0.change_representation(Representation::PowerBasis);
        pk1.change_representation(Representation::PowerBasis);

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];

        cyclo[0] = BigInt::from(1u64); // x^N term
        cyclo[n as usize] = BigInt::from(1u64); // x^0 term

        // Initialize matrices to store results
        let num_moduli = ctx.moduli().len();
        let mut res = PkTrBfvVectors::new(num_moduli, n as usize);

        let pk0_coeffs = pk0.coefficients();
        let pk1_coeffs = pk1.coefficients();

        let pk0_coeffs_rows = pk0_coeffs.rows();
        let pk1_coeffs_rows = pk1_coeffs.rows();

        // Perform the main computation logic
        let results: Vec<(
            usize,
            Vec<BigInt>,
            Vec<BigInt>,
            Vec<BigInt>,
            Vec<BigInt>,
            Vec<BigInt>,
        )> = izip!(ctx.moduli_operators(), pk0_coeffs_rows, pk1_coeffs_rows)
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

                // Calculate pk0i_hat = -a * sk + e
                let pk0i_hat = {
                    let neg_a: Vec<BigInt> = a.iter().map(|a| -a).collect();
                    let pk0i_poly = Polynomial::new(neg_a.clone());
                    let sk_poly = Polynomial::new(sk.clone());
                    let pk0i_times_sk = pk0i_poly.mul(&sk_poly);
                    assert_eq!((pk0i_times_sk.coefficients().len() as u64) - 1, 2 * (n - 1));
                    let e_poly = Polynomial::new(eek.clone());
                    pk0i_times_sk.add(&e_poly).coefficients().to_vec()
                };
                assert_eq!((pk0i_hat.len() as u64) - 1, 2 * (n - 1));

                // Check whether pk0i_hat mod R_qi (the ring) is equal to pk0i
                let mut pk0i_hat_mod_rqi = pk0i_hat.clone();
                reduce_in_ring(&mut pk0i_hat_mod_rqi, &cyclo, &qi_bigint);
                assert_eq!(&pk0i, &pk0i_hat_mod_rqi);

                // Compute r2i numerator = pk0i - pk0i_hat and reduce/center the polynomial
                let pk0i_poly = Polynomial::new(pk0i.clone());
                let pk0i_hat_poly = Polynomial::new(pk0i_hat.clone());
                let pk0i_minus_pk0i_hat = pk0i_poly.sub(&pk0i_hat_poly).coefficients().to_vec();
                assert_eq!((pk0i_minus_pk0i_hat.len() as u64) - 1, 2 * (n - 1));
                let mut pk0i_minus_pk0i_hat_mod_zqi = pk0i_minus_pk0i_hat.clone();
                reduce_and_center_coefficients_mut(&mut pk0i_minus_pk0i_hat_mod_zqi, &qi_bigint);

                // Compute r2i as the quotient of numerator divided by the cyclotomic polynomial
                // to produce: (pk0i - pk0i_hat) / (x^N + 1) mod Z_qi. Remainder should be empty.
                let pk0i_minus_pk0i_hat_poly = Polynomial::new(pk0i_minus_pk0i_hat_mod_zqi.clone());
                let cyclo_poly = Polynomial::new(cyclo.clone());
                let (r2i_poly, r2i_rem_poly) = pk0i_minus_pk0i_hat_poly.div(&cyclo_poly).unwrap();
                let r2i = r2i_poly.coefficients().to_vec();
                let r2i_rem = r2i_rem_poly.coefficients().to_vec();
                assert!(r2i_rem.iter().all(|x| x.is_zero()));
                assert_eq!((r2i.len() as u64) - 1, n - 2); // Order(r2i) = N - 2

                // Assert that (pk0i - pk0i_hat) = (r2i * cyclo) mod Z_qi
                let r2i_poly = Polynomial::new(r2i.clone());
                let r2i_times_cyclo = r2i_poly.mul(&cyclo_poly).coefficients().to_vec();
                let mut r2i_times_cyclo_mod_zqi = r2i_times_cyclo.clone();
                reduce_and_center_coefficients_mut(&mut r2i_times_cyclo_mod_zqi, &qi_bigint);
                assert_eq!(&pk0i_minus_pk0i_hat_mod_zqi, &r2i_times_cyclo_mod_zqi);
                assert_eq!((r2i_times_cyclo.len() as u64) - 1, 2 * (n - 1));

                // Calculate r1i = (pk0i - pk0i_hat - r2i * cyclo) / qi mod Z_p. Remainder should be empty.
                let pk0i_minus_pk0i_hat_poly = Polynomial::new(pk0i_minus_pk0i_hat.clone());
                let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                let r1i_num = pk0i_minus_pk0i_hat_poly
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
                let r1i_poly_check = Polynomial::new(r1i.clone());
                assert_eq!(
                    &r1i_num,
                    &r1i_poly_check.mul(&qi_poly).coefficients().to_vec()
                );

                // Assert that pk0i = pk0i_hat + r1i * qi + r2i * cyclo mod Z_p
                let r1i_poly = Polynomial::new(r1i.clone());
                let r1i_times_qi = r1i_poly.scalar_mul(&qi_bigint).coefficients().to_vec();
                let pk0i_hat_poly = Polynomial::new(pk0i_hat.clone());
                let r1i_times_qi_poly = Polynomial::new(r1i_times_qi.clone());
                let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                let mut pk0i_calculated = pk0i_hat_poly
                    .add(&r1i_times_qi_poly)
                    .add(&r2i_times_cyclo_poly)
                    .coefficients()
                    .to_vec();

                while pk0i_calculated.len() > 0 && pk0i_calculated[0].is_zero() {
                    pk0i_calculated.remove(0);
                }

                assert_eq!(&pk0i, &pk0i_calculated);

                // pk1i = a = pk1
                assert_eq!(&pk1i, &a);
                (i, r2i, r1i, pk0i, pk1i, a.clone())
            })
            .collect();

        // Merge results into the `res` structure after parallel execution
        for (i, r2i, r1i, pk0i, pk1i, a) in results.into_iter() {
            res.r2is[i] = r2i;
            res.r1is[i] = r1i;
            res.pk0is[i] = pk0i;
            res.pk1is[i] = pk1i;
            res.a[i] = a;
        }

        // Set final result vectors
        res.sk = sk;
        res.eek = eek;

        Ok(res)
    }

    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();
        PkTrBfvVectors {
            a: reduce_coefficients_2d(&self.a, zkp_modulus),
            pk0is: reduce_coefficients_2d(&self.pk0is, zkp_modulus),
            pk1is: reduce_coefficients_2d(&self.pk1is, zkp_modulus),
            r1is: reduce_coefficients_2d(&self.r1is, zkp_modulus),
            r2is: reduce_coefficients_2d(&self.r2is, zkp_modulus),
            sk: reduce_coefficients(&self.sk, zkp_modulus),
            eek: reduce_coefficients(&self.eek, zkp_modulus),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "sk": to_string_1d_vec(&self.sk),
            "eek": to_string_1d_vec(&self.eek),
            "a": to_string_2d_vec(&self.a),
            "r2is": to_string_2d_vec(&self.r2is),
            "r1is": to_string_2d_vec(&self.r1is),
            "pk0is": to_string_2d_vec(&self.pk0is),
            "pk1is": to_string_2d_vec(&self.pk1is),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fhe::bfv::{BfvParametersBuilder, SecretKey};
    use rand::{SeedableRng, rngs::StdRng};

    #[test]
    fn test_standard_form() {
        let vecs = PkTrBfvVectors::new(1, 2048);
        let std_form = vecs.standard_form();

        // Check that all vectors are properly reduced
        let p = shared::constants::get_zkp_modulus();
        assert!(std_form.a.iter().flatten().all(|x| x < &p));
        assert!(std_form.eek.iter().all(|x| x < &p));
        assert!(std_form.sk.iter().all(|x| x < &p));
    }

    #[test]
    fn test_vector_computation_to_json() {
        let params = BfvParametersBuilder::new()
            .set_degree(2048)
            .set_plaintext_modulus(1032193)
            .set_moduli(&[0x3FFFFFFF000001])
            .build_arc()
            .unwrap();

        // Use key generation to get the polynomial data
        let mut rng = StdRng::seed_from_u64(0);
        let sk = SecretKey::random(&params, &mut rng);

        // Use extended encryption to get the polynomial data
        let mut rng = StdRng::seed_from_u64(0);
        let (pk, a, sk_rns, eek_rns) = PublicKey::new_extended(&sk, &mut rng).unwrap();
        // Compute vectors
        let vecs = PkTrBfvVectors::compute(&a, &eek_rns, &sk_rns, &pk, &params).unwrap();

        let json = vecs.to_json();

        // Check all required fields are present
        let required_fields = ["pk0is", "pk1is", "a", "eek", "sk", "r2is", "r1is"];

        for field in required_fields.iter() {
            assert!(json.get(field).is_some(), "Missing field: {}", field);
        }
    }
}
