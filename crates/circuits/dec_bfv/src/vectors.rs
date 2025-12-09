//! Input validation vectors for BFV decryption zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct BFV decryption in zero-knowledge.

use bigint_poly::*;
use fhe::bfv::{BfvParameters, Ciphertext, Plaintext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use itertools::izip;
use num_bigint::{BigInt, BigUint};
use num_integer::Integer;
use num_traits::{ToPrimitive, Zero};
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use std::ops::Deref;
use std::sync::Arc;

use shared::errors::{ZkFheError, ZkFheResult};
use shared::utils::{to_string_1d_vec, to_string_2d_vec};

/// Set of vectors for input validation of BFV decryption
#[derive(Clone, Debug)]
pub struct DecBfvVectors {
    pub honest_c0: Vec<Vec<Vec<BigInt>>>, // [H][L][N] - H honest parties, L CRT bases, N coefficients
    pub honest_c1: Vec<Vec<Vec<BigInt>>>, // [H][L][N]
    pub sum_c0: Vec<Vec<BigInt>>,         // [L][N] - Sum of honest ciphertexts
    pub sum_c1: Vec<Vec<BigInt>>,         // [L][N]
    pub s: Vec<Vec<BigInt>>,
    pub u_i: Vec<Vec<BigInt>>,
    pub r_1: Vec<Vec<BigInt>>,
    pub r_2: Vec<Vec<BigInt>>,
    pub u_global: Vec<BigInt>,
    pub crt_quotients: Vec<Vec<BigInt>>,
    pub message: Vec<BigInt>,
}

impl DecBfvVectors {
    /// Create a new `DecBfvVectors` with the given number of moduli, degree, and honest parties.
    pub fn new(num_honest_parties: usize, num_moduli: usize, degree: usize) -> Self {
        DecBfvVectors {
            honest_c0: vec![vec![vec![BigInt::zero(); degree]; num_moduli]; num_honest_parties],
            honest_c1: vec![vec![vec![BigInt::zero(); degree]; num_moduli]; num_honest_parties],
            sum_c0: vec![vec![BigInt::zero(); degree]; num_moduli],
            sum_c1: vec![vec![BigInt::zero(); degree]; num_moduli],
            s: vec![vec![BigInt::zero(); degree]; num_moduli],
            u_i: vec![vec![BigInt::zero(); degree]; num_moduli],
            r_1: vec![vec![BigInt::zero(); 2 * (degree - 1) + 1]; num_moduli],
            r_2: vec![vec![BigInt::zero(); degree - 1]; num_moduli],
            u_global: vec![BigInt::zero(); degree],
            crt_quotients: vec![vec![BigInt::zero(); degree]; num_moduli],
            message: vec![BigInt::zero(); degree],
        }
    }

    /// Create the centered validation vectors for BFV decryption proof.
    ///
    /// This computes all witness polynomials needed to prove:
    /// For each CRT basis i: u_i = c_0i + c_1i * s + r_2_i * (X^N + 1) + r_1_i * q_i
    ///
    /// # Arguments
    ///
    /// * `honest_cts` - H honest ciphertexts from different parties
    /// * `sum_ct` - Sum of all honest ciphertexts
    /// * `pt` - Plaintext (decrypted result)
    /// * `sk` - Secret key used for decryption
    /// * `params` - BFV parameters
    #[allow(clippy::too_many_arguments)]
    pub fn compute(
        honest_cts: &[Ciphertext],
        sum_ct: &Ciphertext,
        pt: &Plaintext,
        sk: &SecretKey,
        params: &Arc<BfvParameters>,
    ) -> ZkFheResult<DecBfvVectors> {
        // Get context and degree
        let ctx = params.ctx_at_level(sum_ct.level)?;
        let n: u64 = ctx.degree as u64;
        let num_honest_parties = honest_cts.len();

        // Extract sum ciphertext components
        let mut sum_ct0 = sum_ct.c[0].clone();
        let mut sum_ct1 = sum_ct.c[1].clone();
        sum_ct0.change_representation(Representation::PowerBasis);
        sum_ct1.change_representation(Representation::PowerBasis);

        // Extract secret key
        let mut sk_poly =
            Poly::try_convert_from(sk.coeffs.as_ref(), ctx, false, Representation::PowerBasis)?;
        sk_poly.change_representation(Representation::PowerBasis);

        // Compute u_rns = c_0 + c_1 * s (intermediate decryption before scaling)
        // This is what we need to prove correct decryption
        let mut s_ntt = sk_poly.clone();
        s_ntt.change_representation(Representation::Ntt);
        let mut sum_ct1_ntt = sum_ct1.clone();
        sum_ct1_ntt.change_representation(Representation::Ntt);
        let mut c1_times_s = &sum_ct1_ntt * &s_ntt;
        c1_times_s.change_representation(Representation::PowerBasis);
        let u_rns = &sum_ct0 + &c1_times_s;

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64); // x^N term (highest degree)
        cyclo[n as usize] = BigInt::from(1u64); // x^0 term (constant)

        // Initialize result structure
        let num_moduli = ctx.moduli().len();
        let mut res = DecBfvVectors::new(num_honest_parties, num_moduli, n as usize);

        let sum_ct0_coeffs = sum_ct0.coefficients();
        let sum_ct1_coeffs = sum_ct1.coefficients();
        let sk_coeffs = sk_poly.coefficients();
        let u_coeffs = u_rns.coefficients();

        let sum_ct0_coeffs_rows = sum_ct0_coeffs.rows();
        let sum_ct1_coeffs_rows = sum_ct1_coeffs.rows();
        let sk_coeffs_rows = sk_coeffs.rows();
        let u_coeffs_rows = u_coeffs.rows();

        // Perform the main computation logic in parallel
        let results: Vec<_> = izip!(
            ctx.moduli_operators(),
            sum_ct0_coeffs_rows,
            sum_ct1_coeffs_rows,
            sk_coeffs_rows,
            u_coeffs_rows,
        )
        .enumerate()
        .par_bridge()
        .map(
            |(i, (qi, sum_ct0_coeffs, sum_ct1_coeffs, sk_coeffs, u_coeffs))| {
                // Convert to vectors of bigint and reverse order
                // NOTE: We keep values in [0, q_i) to ensure they're < u128::MAX
                // Centering is only used for internal computations
                let sum_ct0i: Vec<BigInt> = sum_ct0_coeffs
                    .iter()
                    .rev()
                    .map(|&x| BigInt::from(x))
                    .collect();
                let sum_ct1i: Vec<BigInt> = sum_ct1_coeffs
                    .iter()
                    .rev()
                    .map(|&x| BigInt::from(x))
                    .collect();
                let mut si: Vec<BigInt> =
                    sk_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();
                let mut ui: Vec<BigInt> = u_coeffs.iter().rev().map(|&x| BigInt::from(x)).collect();

                let qi_bigint = BigInt::from(qi.modulus());

                // Do NOT center sum_ct0i and sum_ct1i - they must stay in [0, q_i) to avoid
                // overflow in the circuit's reduce_mod during summation verification.
                // Only center si and ui which are not used in reduce_mod with small values.
                reduce_and_center_coefficients_mut(&mut si, &qi_bigint);
                reduce_and_center_coefficients_mut(&mut ui, &qi_bigint);

                // Calculate u_i_hat = sum_c_0i + sum_c_1i * s
                // Note: sum_ct0i, sum_ct1i are in [0, q_i), si is centered
                // The result will be reduced modulo qi, so mixing is fine
                let ui_hat = {
                    let sum_ct0i_poly = Polynomial::new(sum_ct0i.clone());
                    let sum_ct1i_poly = Polynomial::new(sum_ct1i.clone());
                    let si_poly = Polynomial::new(si.clone());
                    let ct1i_times_s = sum_ct1i_poly.mul(&si_poly);
                    assert_eq!((ct1i_times_s.coefficients().len() as u64) - 1, 2 * (n - 1));

                    sum_ct0i_poly.add(&ct1i_times_s).coefficients().to_vec()
                };
                assert_eq!((ui_hat.len() as u64) - 1, 2 * (n - 1));

                // Check whether ui_hat mod R_qi (the ring) is equal to ui (using centered ui)
                let mut ui_hat_mod_rqi = ui_hat.clone();
                reduce_in_ring(&mut ui_hat_mod_rqi, &cyclo, &qi_bigint);
                assert_eq!(&ui, &ui_hat_mod_rqi);

                // Compute r2i numerator = ui - ui_hat (using centered ui)
                let ui_poly = Polynomial::new(ui.clone());
                let ui_hat_poly = Polynomial::new(ui_hat.clone());
                let ui_minus_ui_hat = ui_poly.sub(&ui_hat_poly).coefficients().to_vec();
                assert_eq!((ui_minus_ui_hat.len() as u64) - 1, 2 * (n - 1));
                let mut ui_minus_ui_hat_mod_zqi = ui_minus_ui_hat.clone();
                reduce_and_center_coefficients_mut(&mut ui_minus_ui_hat_mod_zqi, &qi_bigint);

                // Compute r2i as the quotient: (ui - ui_hat) / (x^N + 1) mod Z_qi
                let ui_minus_ui_hat_poly = Polynomial::new(ui_minus_ui_hat_mod_zqi.clone());
                let cyclo_poly = Polynomial::new(cyclo.clone());
                let (r2i_poly, r2i_rem_poly) = ui_minus_ui_hat_poly.div(&cyclo_poly).unwrap();
                let r2i = r2i_poly.coefficients().to_vec();
                let r2i_rem = r2i_rem_poly.coefficients().to_vec();
                assert!(r2i_rem.iter().all(|x| x.is_zero()));
                assert_eq!((r2i.len() as u64) - 1, n - 2); // Order(r2i) = N - 2

                // Assert that (ui - ui_hat) = (r2i * cyclo) mod Z_qi
                let r2i_poly = Polynomial::new(r2i.clone());
                let r2i_times_cyclo = r2i_poly.mul(&cyclo_poly).coefficients().to_vec();
                let mut r2i_times_cyclo_mod_zqi = r2i_times_cyclo.clone();
                reduce_and_center_coefficients_mut(&mut r2i_times_cyclo_mod_zqi, &qi_bigint);
                assert_eq!(&ui_minus_ui_hat_mod_zqi, &r2i_times_cyclo_mod_zqi);
                assert_eq!((r2i_times_cyclo.len() as u64) - 1, 2 * (n - 1));

                // Calculate r1i = (ui - ui_hat - r2i * cyclo) / qi mod Z_p
                let ui_minus_ui_hat_poly = Polynomial::new(ui_minus_ui_hat.clone());
                let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                let r1i_num = ui_minus_ui_hat_poly
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

                // Assert that ui = ui_hat + r1i * qi + r2i * cyclo mod Z_p
                let r1i_poly = Polynomial::new(r1i.clone());
                let r1i_times_qi = r1i_poly.scalar_mul(&qi_bigint).coefficients().to_vec();
                let ui_hat_poly = Polynomial::new(ui_hat.clone());
                let r1i_times_qi_poly = Polynomial::new(r1i_times_qi.clone());
                let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                let mut ui_calculated = ui_hat_poly
                    .add(&r1i_times_qi_poly)
                    .add(&r2i_times_cyclo_poly)
                    .coefficients()
                    .to_vec();

                while !ui_calculated.is_empty() && ui_calculated[0].is_zero() {
                    ui_calculated.remove(0);
                }

                // Compare centered ui with calculated (both are in centered form)
                assert_eq!(&ui, &ui_calculated);

                // Keep values in centered form (like dec_share_trbfv does)
                // reduce_coefficients_2d in standard_form() will handle conversion to zkp field
                (i, sum_ct0i, sum_ct1i, si, ui, r1i, r2i)
            },
        )
        .collect();

        // Merge results into the `res` structure after parallel execution
        for (i, sum_ct0i, sum_ct1i, si, ui, r1i, r2i) in results.into_iter() {
            res.sum_c0[i] = sum_ct0i;
            res.sum_c1[i] = sum_ct1i;
            res.s[i] = si;
            res.u_i[i] = ui;
            res.r_1[i] = r1i;
            res.r_2[i] = r2i;
        }

        // Extract honest ciphertexts - keep in [0, q_i) to avoid overflow in reduce_mod
        for (party_idx, ct) in honest_cts.iter().enumerate() {
            let mut ct0 = ct.c[0].clone();
            let mut ct1 = ct.c[1].clone();
            ct0.change_representation(Representation::PowerBasis);
            ct1.change_representation(Representation::PowerBasis);

            let ct0_coeffs = ct0.coefficients();
            let ct1_coeffs = ct1.coefficients();

            for (basis_idx, (_qi, ct0_row, ct1_row)) in
                izip!(ctx.moduli_operators(), ct0_coeffs.rows(), ct1_coeffs.rows()).enumerate()
            {
                // Keep in [0, q_i) - do NOT center to avoid u128 overflow in circuit's reduce_mod
                let ct0i: Vec<BigInt> = ct0_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                let ct1i: Vec<BigInt> = ct1_row.iter().rev().map(|&x| BigInt::from(x)).collect();

                res.honest_c0[party_idx][basis_idx] = ct0i;
                res.honest_c1[party_idx][basis_idx] = ct1i;
            }
        }

        // Compute u_global via CRT reconstruction
        // Reconstruct the full value in Z[X] from per-modulus values using CRT
        use fhe_math::rns::RnsContext;
        use ndarray::ArrayView1;

        let rns = RnsContext::new(ctx.moduli()).map_err(|e| ZkFheError::Bfv {
            message: format!("Failed to create RNS context: {:?}", e),
        })?;

        // First, we need to convert u_i (which are centered BigInt) back to positive u64 residues
        let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();
        for (m, ui) in res.u_i.iter().enumerate() {
            let q_m = ctx.moduli()[m];
            let q_m_bigint = BigInt::from(q_m);
            let mut u_m: Vec<u64> = Vec::new();

            for coeff in ui.iter() {
                // Convert centered coefficient back to [0, q_m)
                let mut val = coeff % &q_m_bigint;
                if val < BigInt::zero() {
                    val += &q_m_bigint;
                }
                u_m.push(val.to_u64().expect("Coefficient should fit in u64"));
            }
            u_per_modulus.push(u_m);
        }

        // Perform CRT reconstruction coefficient-wise
        let mut u_global_coeffs: Vec<BigUint> = Vec::new();
        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..n as usize {
            // Collect per-modulus values for this coefficient
            let rests: Vec<u64> = (0..num_moduli)
                .map(|m| u_per_modulus[m][coeff_idx])
                .collect();

            // CRT reconstruction: u_global[coeff_idx] = CRT([u^{(0)}[coeff_idx], u^{(1)}[coeff_idx], ...])
            // This returns the unique value in [0, Q) where Q = q_0 * q_1 * ... * q_{L-1}
            let u_global_coeff = rns.lift(ArrayView1::from(&rests));
            u_global_coeffs.push(u_global_coeff);
        }

        // Convert to BigInt - keep in [0, Q) range, do NOT center
        // The circuit handles centering itself in verify_decoding
        let _q_product: BigInt = ctx.moduli().iter().map(|&q| BigInt::from(q)).product();
        let u_global: Vec<BigInt> = u_global_coeffs
            .iter()
            .map(|x| BigInt::from(x.clone()))
            .collect();

        // Verify CRT reconstruction: u_global mod q_i == u_i for all moduli
        // IMPORTANT: Use the centered u_i values we stored, and normalize for comparison
        for m in 0..num_moduli {
            let q_m = ctx.moduli()[m];
            let q_m_bigint = BigInt::from(q_m);
            for (coeff_idx, u_global_val) in u_global.iter().enumerate().take(n as usize) {
                // Reduce u_global mod q_m and normalize to [0, q_m)
                let u_global_mod_qm = u_global_val % &q_m_bigint;
                let u_global_mod_qm_normalized = if u_global_mod_qm < BigInt::zero() {
                    &u_global_mod_qm + &q_m_bigint
                } else {
                    u_global_mod_qm.clone()
                };

                // Get the centered u_i value we stored and normalize it to [0, q_m) for comparison
                let u_i_centered = &res.u_i[m][coeff_idx];
                let u_i_mod_qm = u_i_centered % &q_m_bigint;
                let u_i_normalized = if u_i_mod_qm < BigInt::zero() {
                    &u_i_mod_qm + &q_m_bigint
                } else {
                    u_i_mod_qm.clone()
                };

                if u_global_mod_qm_normalized != u_i_normalized {
                    return Err(ZkFheError::Bfv {
                        message: format!(
                            "CRT reconstruction verification failed: u_global[{}] mod q_{} = {}, but u_i[{}][{}] normalized = {}",
                            coeff_idx, m, u_global_mod_qm_normalized, m, coeff_idx, u_i_normalized
                        ),
                    });
                }
            }
        }

        res.u_global = u_global.clone();

        // Compute CRT quotients: r^{(m)} = (u_global - u^{(m)}) / q_m
        // For each modulus m, this satisfies: u^{(m)} + r^{(m)} * q_m = u_global
        // IMPORTANT: Use the centered u_i values that we actually stored, not the [0, q_m) versions
        for m in 0..num_moduli {
            let q_m = ctx.moduli()[m];
            let q_m_bigint = BigInt::from(q_m);
            let mut r_m_coeffs: Vec<BigInt> = Vec::new();

            for (coeff_idx, u_global_val) in u_global.iter().enumerate().take(n as usize) {
                let u_m = &res.u_i[m][coeff_idx]; // Use the centered value we stored

                // Compute: r^{(m)}[coeff_idx] = (u_global[coeff_idx] - u^{(m)}[coeff_idx]) / q_m
                let diff = u_global_val - u_m;
                let quotient = &diff / &q_m_bigint;
                let remainder = &diff % &q_m_bigint;

                // Verify the division is exact (should always be true by CRT property)
                if !remainder.is_zero() {
                    return Err(ZkFheError::Bfv {
                        message: format!(
                            "CRT quotient computation failed: division not exact. u_global[{}]={}, u^({})[{}]={}, q_m={}, remainder={}",
                            coeff_idx, u_global_val, m, coeff_idx, u_m, q_m_bigint, remainder
                        ),
                    });
                }

                r_m_coeffs.push(quotient);
            }

            res.crt_quotients[m] = r_m_coeffs;
        }

        // Extract message from plaintext (keep in [0, t) form to ensure < u128::MAX)
        let message: Vec<BigInt> = pt
            .value
            .deref()
            .iter()
            .rev()
            .map(|&x| BigInt::from(x))
            .collect();
        res.message = message;

        // Verify decoding (mimics circuit's verify_decoding function)
        // TODO: Uncomment this when the circuit is updated to use the new verify_decoding function
        res.verify_decoding_rust(ctx, params)?;

        Ok(res)
    }

    // Verify decoding in Rust (mimics the circuit's verify_direct_decoding function)
    // This helps catch issues before running the circuit
    fn verify_decoding_rust(
        &self,
        ctx: &Arc<fhe_math::rq::Context>,
        params: &Arc<BfvParameters>,
    ) -> ZkFheResult<()> {
        let n = ctx.degree;
        let t = BigInt::from(params.plaintext());

        // Compute Q = product of all moduli
        let mut q_modulus = BigInt::from(1u64);
        for &q_i in ctx.moduli() {
            q_modulus *= BigInt::from(q_i);
        }

        // Compute Q^{-1} mod t using extended Euclidean algorithm
        let q_inverse_mod_t = {
            let gcd_result = q_modulus.extended_gcd(&t);
            if gcd_result.gcd != BigInt::from(1) {
                return Err(ZkFheError::Bfv {
                    message: format!("Q and t are not coprime, gcd = {}", gcd_result.gcd),
                });
            }
            // Ensure the inverse is positive
            let inv = gcd_result.x % &t;
            if inv < BigInt::zero() { inv + &t } else { inv }
        };

        let q_half = &q_modulus / BigInt::from(2);

        // Verify decoding for each coefficient
        for coeff_idx in 0..n {
            let u_global_coeff = &self.u_global[coeff_idx];
            let message_coeff = &self.message[coeff_idx];

            // Compute (t * u_global) mod Q
            let t_times_u = (u_global_coeff * &t) % &q_modulus;

            // Check if centering is needed: (t*u) mod Q >= Q/2
            let needs_centering = t_times_u > q_half;

            let computed_message = if needs_centering {
                // When (t*u) mod Q >= Q/2: treat as negative in centered form
                // Conceptually: (t*u)_Q - Q (negative value)
                // -Q^{-1} * (negative) = positive result
                let centered_positive = &q_modulus - &t_times_u;
                (&q_inverse_mod_t * centered_positive) % &t
            } else {
                // When (t*u) mod Q < Q/2: stays positive in centered form
                // -Q^{-1} * (positive) = negative result = t - result
                let product = (&q_inverse_mod_t * &t_times_u) % &t;
                if product == BigInt::zero() {
                    BigInt::zero()
                } else {
                    &t - product
                }
            };

            // Verify: only check non-zero coefficients (mimics Noir circuit behavior)
            if *message_coeff != BigInt::zero() && computed_message != *message_coeff {
                return Err(ZkFheError::Bfv {
                    message: format!(
                        "Decoding verification failed at coefficient {}: expected message = {}, computed message = {}. \
                        This means the decryption is incorrect. Check ciphertext and secret key inputs.",
                        coeff_idx, message_coeff, computed_message
                    ),
                });
            }
        }

        Ok(())
    }
}

impl DecBfvVectors {
    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();

        // Reduce honest ciphertexts (3D: parties x bases x coefficients)
        let honest_c0_reduced: Vec<Vec<Vec<BigInt>>> = self
            .honest_c0
            .iter()
            .map(|party_c0| reduce_coefficients_2d(party_c0, zkp_modulus))
            .collect();
        let honest_c1_reduced: Vec<Vec<Vec<BigInt>>> = self
            .honest_c1
            .iter()
            .map(|party_c1| reduce_coefficients_2d(party_c1, zkp_modulus))
            .collect();

        let result = DecBfvVectors {
            honest_c0: honest_c0_reduced,
            honest_c1: honest_c1_reduced,
            sum_c0: reduce_coefficients_2d(&self.sum_c0, zkp_modulus),
            sum_c1: reduce_coefficients_2d(&self.sum_c1, zkp_modulus),
            s: reduce_coefficients_2d(&self.s, zkp_modulus),
            u_i: reduce_coefficients_2d(&self.u_i, zkp_modulus),
            r_1: reduce_coefficients_2d(&self.r_1, zkp_modulus),
            r_2: reduce_coefficients_2d(&self.r_2, zkp_modulus),
            u_global: reduce_coefficients(&self.u_global, zkp_modulus),
            crt_quotients: reduce_coefficients_2d(&self.crt_quotients, zkp_modulus),
            message: reduce_coefficients(&self.message, zkp_modulus),
        };

        // Note: We don't validate u128::MAX constraints here because:
        // 1. Centered values (like s with -1) become large after reduce_coefficients_2d
        // 2. The Noir circuit handles these large values correctly in Field arithmetic
        // 3. Only values used in reduce_mod need special handling, and those work correctly
        result.validate_for_circuit(zkp_modulus);

        result
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "honest_c0": self.honest_c0.iter().map(|party| to_string_2d_vec(party)).collect::<Vec<_>>(),
            "honest_c1": self.honest_c1.iter().map(|party| to_string_2d_vec(party)).collect::<Vec<_>>(),
            "sum_c0": to_string_2d_vec(&self.sum_c0),
            "sum_c1": to_string_2d_vec(&self.sum_c1),
            "s": to_string_2d_vec(&self.s),
            "u_i": to_string_2d_vec(&self.u_i),
            "r_1": to_string_2d_vec(&self.r_1),
            "r_2": to_string_2d_vec(&self.r_2),
            "u_global": to_string_1d_vec(&self.u_global),
            "crt_quotients": to_string_2d_vec(&self.crt_quotients),
            "message": to_string_1d_vec(&self.message),
        })
    }

    /// Validates that all values meet the requirements for the circuit:
    /// 1. All values are in [0, zkp_modulus) range
    /// 2. Small values (honest ciphertexts, sum ciphertexts, secret key, message, u_i, r_2)
    ///    must be < 2^128 for u128 casting in reduce_mod operations
    /// 3. Large values (u_global, crt_quotients, r_1) can be > 2^128 but must be < zkp_modulus
    ///    Note: These large values will cause u128 casting to wrap in __compute_mod_reduction,
    ///    but the remainder computation will still be correct for small moduli (< 2^56).
    ///    The assertion in reduce_mod will catch any issues.
    ///
    /// Validates that all values meet the requirements for the circuit:
    /// 1. All values are in [0, zkp_modulus) range
    /// 2. Values that must be < 2^128 for u128 casting in reduce_mod:
    ///    - honest_c0, honest_c1: used in Field sum then reduce_mod
    ///    - sum_c0, sum_c1: compared after reduce_mod
    ///    - message: decoded message, must be small
    ///
    /// 3. Values that can be > 2^128 (only used in Field arithmetic):
    ///    - s: range_check_2bounds, eval
    ///    - u_i: range_check_2bounds, eval, add (CRT)
    ///    - r_1: eval (quotient polynomial)
    ///    - r_2: range_check_2bounds, eval (quotient polynomial)
    ///    - u_global: add, mul, equality (CRT reconstruction)
    ///    - crt_quotients: mul, add, equality (CRT verification)
    fn validate_for_circuit(&self, zkp_modulus: &BigInt) {
        let u128_max = BigInt::from(u128::MAX);

        // Check honest_c0 - must be small (< 2^128) since they're ciphertext coefficients
        for (party_idx, party_c0) in self.honest_c0.iter().enumerate() {
            for (mod_idx, modulus_row) in party_c0.iter().enumerate() {
                for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "honest_c0[{}][{}][{}] = {} is negative",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "honest_c0[{}][{}][{}] = {} >= zkp_modulus = {}",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                    assert!(
                        coeff <= &u128_max,
                        "honest_c0[{}][{}][{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff,
                        u128_max
                    );
                }
            }
        }

        // Check honest_c1 - must be small (< 2^128) since they're ciphertext coefficients
        for (party_idx, party_c1) in self.honest_c1.iter().enumerate() {
            for (mod_idx, modulus_row) in party_c1.iter().enumerate() {
                for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "honest_c1[{}][{}][{}] = {} is negative",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "honest_c1[{}][{}][{}] = {} >= zkp_modulus = {}",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                    assert!(
                        coeff <= &u128_max,
                        "honest_c1[{}][{}][{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff,
                        u128_max
                    );
                }
            }
        }

        // Check sum_c0 - must be small (< 2^128) since it's a ciphertext coefficient
        for (mod_idx, modulus_row) in self.sum_c0.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "sum_c0[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "sum_c0[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
                assert!(
                    coeff <= &u128_max,
                    "sum_c0[{}][{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    u128_max
                );
            }
        }

        // Check sum_c1 - must be small (< 2^128) since it's a ciphertext coefficient
        for (mod_idx, modulus_row) in self.sum_c1.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "sum_c1[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "sum_c1[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
                assert!(
                    coeff <= &u128_max,
                    "sum_c1[{}][{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    u128_max
                );
            }
        }

        // Check s (secret key) - can be large (> 2^128) after reduce_coefficients_2d
        // These values are only used in Field arithmetic (range_check_2bounds, eval),
        // not in reduce_mod with small moduli, so u128::MAX check is not needed
        for (mod_idx, modulus_row) in self.s.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "s[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "s[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check u_i - can be large (> 2^128) after reduce_coefficients_2d
        // These values are only used in Field arithmetic (range_check_2bounds, eval, add),
        // not in reduce_mod with small moduli, so u128::MAX check is not needed
        for (mod_idx, modulus_row) in self.u_i.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "u_i[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "u_i[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check r_1 - can be large (> 2^128) since it's a quotient by q_i
        // These values are only used in Field arithmetic (multiplication, addition, equality),
        // not in reduce_mod with small moduli, so u128::MAX check is not needed
        for (mod_idx, modulus_row) in self.r_1.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "r_1[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "r_1[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check r_2 - can be large (> 2^128) after reduce_coefficients_2d
        // These values are only used in Field arithmetic (range_check_2bounds, eval),
        // not in reduce_mod with small moduli, so u128::MAX check is not needed
        for (mod_idx, modulus_row) in self.r_2.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "r_2[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "r_2[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check u_global - can be large (> 2^128) since it's CRT reconstruction
        // These values are only used in Field arithmetic (addition, multiplication, equality),
        // not in reduce_mod with small moduli, so u128::MAX check is not needed
        for (idx, coeff) in self.u_global.iter().enumerate() {
            assert!(
                coeff >= &BigInt::zero(),
                "u_global[{}] = {} is negative",
                idx,
                coeff
            );
            assert!(
                coeff < zkp_modulus,
                "u_global[{}] = {} >= zkp_modulus = {}",
                idx,
                coeff,
                zkp_modulus
            );
        }

        // Check crt_quotients - can be large (> 2^128) since they're derived from u_global
        // These values are only used in Field arithmetic (multiplication, addition, equality),
        // not in reduce_mod with small moduli, so u128::MAX check is not needed
        for (mod_idx, modulus_row) in self.crt_quotients.iter().enumerate() {
            for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "crt_quotients[{}][{}] = {} is negative",
                    mod_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "crt_quotients[{}][{}] = {} >= zkp_modulus = {}",
                    mod_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check message - must be small (< 2^128)
        for (idx, coeff) in self.message.iter().enumerate() {
            assert!(
                coeff >= &BigInt::zero(),
                "message[{}] = {} is negative",
                idx,
                coeff
            );
            assert!(
                coeff < zkp_modulus,
                "message[{}] = {} >= zkp_modulus = {}",
                idx,
                coeff,
                zkp_modulus
            );
            assert!(
                coeff <= &u128_max,
                "message[{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                idx,
                coeff,
                u128_max
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_decryption;
    use shared::circuit::SampleType;
    use shared::utils::test_parameters_bfv;

    #[test]
    fn test_vector_computation() {
        let params = test_parameters_bfv();
        let data =
            generate_sample_decryption(&params, &params, SampleType::SecretKey, None).unwrap();

        let vectors = DecBfvVectors::compute(
            &data.honest_ciphertexts,
            &data.sum_ciphertext,
            &data.message,
            &data.secret_key,
            &params,
        )
        .unwrap();

        // Verify structure
        assert_eq!(vectors.honest_c0.len(), data.num_honest_parties);
        assert_eq!(vectors.sum_c0.len(), params.moduli().len());
        assert_eq!(vectors.sum_c1.len(), params.moduli().len());
        assert_eq!(vectors.s.len(), params.moduli().len());
        assert_eq!(vectors.u_i.len(), params.moduli().len());
    }

    #[test]
    fn test_standard_form() {
        let vecs = DecBfvVectors::new(3, 2, 2048);
        let std_form = vecs.standard_form();

        // Check that all vectors are properly reduced
        let p = shared::constants::get_zkp_modulus();
        assert!(std_form.u_global.iter().all(|x| x < &p));
        assert!(std_form.message.iter().all(|x| x < &p));
    }

    #[test]
    fn test_validation_with_real_data() {
        let params = test_parameters_bfv();
        let data =
            generate_sample_decryption(&params, &params, SampleType::SecretKey, None).unwrap();

        let vectors = DecBfvVectors::compute(
            &data.honest_ciphertexts,
            &data.sum_ciphertext,
            &data.message,
            &data.secret_key,
            &params,
        )
        .unwrap();

        // Convert to standard form (this will call validate_for_circuit)
        let std_form = vectors.standard_form();

        // If we get here, validation passed
        let zkp_modulus = shared::constants::get_zkp_modulus();

        // Spot check a few values
        assert!(
            std_form
                .u_global
                .iter()
                .all(|x| x >= &BigInt::zero() && x < &zkp_modulus)
        );
        assert!(
            std_form
                .message
                .iter()
                .all(|x| x >= &BigInt::zero() && x < &zkp_modulus)
        );

        // Check that small values are within u128::MAX
        let u128_max = BigInt::from(u128::MAX);
        assert!(std_form.message.iter().all(|x| x <= &u128_max));
    }
}
