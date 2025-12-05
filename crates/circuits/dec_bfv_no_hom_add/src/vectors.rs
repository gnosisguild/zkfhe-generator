//! Input validation vectors for BFV decryption (no homomorphic addition) zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct BFV decryption in zero-knowledge.
//!
//! Structure matches the Noir circuit:
//! - honest_c0[H][L][L'][N]: Ciphertext component 0 for each party, TRBFV basis, BFV basis
//! - honest_c1[H][L][L'][N]: Ciphertext component 1
//! - s[N]: BFV secret key (single polynomial)
//! - u_i[H][L][L'][N]: Per-ciphertext per-BFV-basis decryption result
//! - r_1[H][L][L'][2N-1]: Modulus quotient polynomials
//! - r_2[H][L][L'][N-1]: Cyclotomic quotient polynomials
//! - u_global[H][L][N]: CRT reconstructed polynomials
//! - crt_quotients[H][L][L'][N]: CRT lifting quotients
//! - decrypted_shares[H][L][N]: Decoded message polynomials
//! - expected_aggregated_shares[L][N]: Aggregated TRBFV shares

use bigint_poly::*;
use fhe::bfv::{BfvParameters, Ciphertext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use itertools::izip;
use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use std::sync::Arc;

use shared::errors::{ZkFheError, ZkFheResult};
use shared::utils::{to_string_1d_vec, to_string_2d_vec, to_string_3d_vec, to_string_4d_vec};

/// Set of vectors for input validation of BFV decryption (no homomorphic addition)
#[derive(Clone, Debug)]
pub struct DecBfvNoHomAddVectors {
    /// Ciphertext c0 components: [H][L][L'][N]
    pub honest_c0: Vec<Vec<Vec<Vec<BigInt>>>>,
    /// Ciphertext c1 components: [H][L][L'][N]
    pub honest_c1: Vec<Vec<Vec<Vec<BigInt>>>>,
    /// BFV secret key: [N] (single polynomial)
    pub s: Vec<BigInt>,
    /// Per-ciphertext per-BFV-basis decryption results: [H][L][L'][N]
    pub u_i: Vec<Vec<Vec<Vec<BigInt>>>>,
    /// Modulus quotient polynomials: [H][L][L'][2N-1]
    pub r_1: Vec<Vec<Vec<Vec<BigInt>>>>,
    /// Cyclotomic quotient polynomials: [H][L][L'][N-1]
    pub r_2: Vec<Vec<Vec<Vec<BigInt>>>>,
    /// CRT reconstructed polynomials: [H][L][N]
    pub u_global: Vec<Vec<Vec<BigInt>>>,
    /// CRT lifting quotients: [H][L][L'][N]
    pub crt_quotients: Vec<Vec<Vec<Vec<BigInt>>>>,
    /// Decoded message polynomials: [H][L][N]
    pub decrypted_shares: Vec<Vec<Vec<BigInt>>>,
    /// Aggregated TRBFV shares: [L][N]
    pub expected_aggregated_shares: Vec<Vec<BigInt>>,
}

impl DecBfvNoHomAddVectors {
    /// Create a new `DecBfvNoHomAddVectors` with the given dimensions
    pub fn new(
        num_honest_parties: usize,
        num_trbfv_bases: usize,
        num_bfv_bases: usize,
        degree: usize,
    ) -> Self {
        DecBfvNoHomAddVectors {
            honest_c0: vec![
                vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases];
                num_honest_parties
            ],
            honest_c1: vec![
                vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases];
                num_honest_parties
            ],
            s: vec![BigInt::zero(); degree],
            u_i: vec![
                vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases];
                num_honest_parties
            ],
            r_1: vec![
                vec![
                    vec![vec![BigInt::zero(); 2 * degree - 1]; num_bfv_bases];
                    num_trbfv_bases
                ];
                num_honest_parties
            ],
            r_2: vec![
                vec![vec![vec![BigInt::zero(); degree - 1]; num_bfv_bases]; num_trbfv_bases];
                num_honest_parties
            ],
            u_global: vec![vec![vec![BigInt::zero(); degree]; num_trbfv_bases]; num_honest_parties],
            crt_quotients: vec![
                vec![
                    vec![vec![BigInt::zero(); degree]; num_bfv_bases];
                    num_trbfv_bases
                ];
                num_honest_parties
            ],
            decrypted_shares: vec![
                vec![vec![BigInt::zero(); degree]; num_trbfv_bases];
                num_honest_parties
            ],
            expected_aggregated_shares: vec![vec![BigInt::zero(); degree]; num_trbfv_bases],
        }
    }

    /// Create the validation vectors for BFV decryption (no homomorphic addition) proof.
    ///
    /// This computes all witness polynomials needed to prove:
    /// For each ciphertext (h, l) and each BFV CRT basis l':
    ///   u_i[h][l][l'] = c_0[h][l][l'] + c_1[h][l][l'] * s + r_2[h][l][l'] * (X^N + 1) + r_1[h][l][l'] * q'_{l'}
    ///
    /// # Arguments
    ///
    /// * `honest_cts` - H*L ciphertexts [party_idx][trbfv_basis]
    /// * `sk` - BFV secret key used for decryption
    /// * `bfv_params` - BFV parameters
    /// * `trbfv_params` - TRBFV parameters
    pub fn compute(
        honest_cts: &[Vec<Ciphertext>],
        sk: &SecretKey,
        bfv_params: &Arc<BfvParameters>,
        trbfv_params: &Arc<BfvParameters>,
    ) -> ZkFheResult<Self> {
        let ctx = bfv_params.ctx_at_level(0)?;
        let n: u64 = ctx.degree as u64;
        let num_honest_parties = honest_cts.len();
        let num_trbfv_bases = trbfv_params.moduli().len();
        let num_bfv_bases = bfv_params.moduli().len();

        // Extract secret key
        let mut sk_poly =
            Poly::try_convert_from(sk.coeffs.as_ref(), ctx, false, Representation::PowerBasis)?;
        sk_poly.change_representation(Representation::PowerBasis);

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64);
        cyclo[n as usize] = BigInt::from(1u64);

        // Initialize result structure
        let mut res = DecBfvNoHomAddVectors::new(
            num_honest_parties,
            num_trbfv_bases,
            num_bfv_bases,
            n as usize,
        );

        // Extract secret key coefficients (centered)
        let sk_coeffs = sk_poly.coefficients();
        for (bfv_idx, qi) in ctx.moduli_operators().iter().enumerate() {
            let qi_bigint = BigInt::from(qi.modulus());
            let sk_row = sk_coeffs.row(bfv_idx);
            let mut si: Vec<BigInt> = sk_row.iter().rev().map(|&x| BigInt::from(x)).collect();
            reduce_and_center_coefficients_mut(&mut si, &qi_bigint);

            // Store the first BFV basis's secret key as the canonical s
            // (they should all be the same after centering)
            if bfv_idx == 0 {
                res.s = si.clone();
            }
        }

        // Process each ciphertext
        for (party_idx, party_cts) in honest_cts.iter().enumerate().take(num_honest_parties) {
            for (trbfv_idx, ct) in party_cts.iter().enumerate().take(num_trbfv_bases) {
                // Extract ciphertext components
                let mut ct0 = ct.c[0].clone();
                let mut ct1 = ct.c[1].clone();
                ct0.change_representation(Representation::PowerBasis);
                ct1.change_representation(Representation::PowerBasis);

                // Compute u_rns = c_0 + c_1 * s
                let mut s_ntt = sk_poly.clone();
                s_ntt.change_representation(Representation::Ntt);
                let mut ct1_ntt = ct1.clone();
                ct1_ntt.change_representation(Representation::Ntt);
                let mut c1_times_s = &ct1_ntt * &s_ntt;
                c1_times_s.change_representation(Representation::PowerBasis);
                let u_rns = &ct0 + &c1_times_s;

                let ct0_coeffs = ct0.coefficients();
                let ct1_coeffs = ct1.coefficients();
                let u_coeffs = u_rns.coefficients();

                // Process each BFV basis
                let results: Vec<_> = izip!(
                    ctx.moduli_operators(),
                    ct0_coeffs.rows(),
                    ct1_coeffs.rows(),
                    sk_coeffs.rows(),
                    u_coeffs.rows(),
                )
                .enumerate()
                .par_bridge()
                .map(|(bfv_idx, (qi, ct0_row, ct1_row, sk_row, u_row))| {
                    let qi_bigint = BigInt::from(qi.modulus());

                    // Convert to BigInt vectors (reversed for polynomial representation)
                    let ct0i: Vec<BigInt> =
                        ct0_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                    let ct1i: Vec<BigInt> =
                        ct1_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                    let mut si: Vec<BigInt> =
                        sk_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                    let mut ui: Vec<BigInt> =
                        u_row.iter().rev().map(|&x| BigInt::from(x)).collect();

                    // Center si and ui
                    reduce_and_center_coefficients_mut(&mut si, &qi_bigint);
                    reduce_and_center_coefficients_mut(&mut ui, &qi_bigint);

                    // Calculate u_i_hat = c_0i + c_1i * s
                    let ui_hat = {
                        let ct0i_poly = Polynomial::new(ct0i.clone());
                        let ct1i_poly = Polynomial::new(ct1i.clone());
                        let si_poly = Polynomial::new(si.clone());
                        let ct1i_times_s = ct1i_poly.mul(&si_poly);
                        ct0i_poly.add(&ct1i_times_s).coefficients().to_vec()
                    };

                    // Compute r2i numerator = ui - ui_hat
                    let ui_poly = Polynomial::new(ui.clone());
                    let ui_hat_poly = Polynomial::new(ui_hat.clone());
                    let ui_minus_ui_hat = ui_poly.sub(&ui_hat_poly).coefficients().to_vec();
                    let mut ui_minus_ui_hat_mod_zqi = ui_minus_ui_hat.clone();
                    reduce_and_center_coefficients_mut(&mut ui_minus_ui_hat_mod_zqi, &qi_bigint);

                    // Compute r2i = (ui - ui_hat) / (x^N + 1) mod Z_qi
                    let ui_minus_ui_hat_poly = Polynomial::new(ui_minus_ui_hat_mod_zqi.clone());
                    let cyclo_poly = Polynomial::new(cyclo.clone());
                    let (r2i_poly, _) = ui_minus_ui_hat_poly.div(&cyclo_poly).unwrap();
                    let r2i = r2i_poly.coefficients().to_vec();

                    // Compute r2i * cyclo
                    let r2i_poly = Polynomial::new(r2i.clone());
                    let r2i_times_cyclo = r2i_poly.mul(&cyclo_poly).coefficients().to_vec();

                    // Calculate r1i = (ui - ui_hat - r2i * cyclo) / qi
                    let ui_minus_ui_hat_poly = Polynomial::new(ui_minus_ui_hat.clone());
                    let r2i_times_cyclo_poly = Polynomial::new(r2i_times_cyclo.clone());
                    let r1i_num = ui_minus_ui_hat_poly
                        .sub(&r2i_times_cyclo_poly)
                        .coefficients()
                        .to_vec();

                    let r1i_num_poly = Polynomial::new(r1i_num);
                    let qi_poly = Polynomial::new(vec![qi_bigint.clone()]);
                    let (r1i_poly, _) = r1i_num_poly.div(&qi_poly).unwrap();
                    let r1i = r1i_poly.coefficients().to_vec();

                    (bfv_idx, ct0i, ct1i, ui, r1i, r2i)
                })
                .collect();

                // Store results
                for (bfv_idx, ct0i, ct1i, ui, r1i, r2i) in results {
                    res.honest_c0[party_idx][trbfv_idx][bfv_idx] = ct0i;
                    res.honest_c1[party_idx][trbfv_idx][bfv_idx] = ct1i;
                    res.u_i[party_idx][trbfv_idx][bfv_idx] = ui;
                    res.r_1[party_idx][trbfv_idx][bfv_idx] = r1i;
                    res.r_2[party_idx][trbfv_idx][bfv_idx] = r2i;
                }

                // Compute u_global via CRT reconstruction for this ciphertext
                let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();
                for bfv_idx in 0..num_bfv_bases {
                    let q_m = ctx.moduli()[bfv_idx];
                    let q_m_bigint = BigInt::from(q_m);
                    let mut u_m: Vec<u64> = Vec::new();

                    for coeff in res.u_i[party_idx][trbfv_idx][bfv_idx].iter() {
                        let mut val = coeff % &q_m_bigint;
                        if val < BigInt::zero() {
                            val += &q_m_bigint;
                        }
                        u_m.push(val.to_u64().expect("Coefficient should fit in u64"));
                    }
                    u_per_modulus.push(u_m);
                }

                // CRT reconstruction
                use fhe_math::rns::RnsContext;
                use ndarray::ArrayView1;

                let rns = RnsContext::new(ctx.moduli()).map_err(|e| ZkFheError::Bfv {
                    message: format!("Failed to create RNS context: {:?}", e),
                })?;

                let mut u_global_coeffs: Vec<BigUint> = Vec::new();
                #[allow(clippy::needless_range_loop)]
                for coeff_idx in 0..n as usize {
                    let rests: Vec<u64> = (0..num_bfv_bases)
                        .map(|m| u_per_modulus[m][coeff_idx])
                        .collect();
                    let u_global_coeff = rns.lift(ArrayView1::from(&rests));
                    u_global_coeffs.push(u_global_coeff);
                }

                let u_global: Vec<BigInt> = u_global_coeffs
                    .iter()
                    .map(|x| BigInt::from(x.clone()))
                    .collect();
                res.u_global[party_idx][trbfv_idx] = u_global.clone();

                // Compute CRT quotients
                for bfv_idx in 0..num_bfv_bases {
                    let q_m = ctx.moduli()[bfv_idx];
                    let q_m_bigint = BigInt::from(q_m);
                    let mut r_m_coeffs: Vec<BigInt> = Vec::new();

                    for (coeff_idx, u_global_val) in u_global.iter().enumerate().take(n as usize) {
                        let u_m = &res.u_i[party_idx][trbfv_idx][bfv_idx][coeff_idx];
                        let diff = u_global_val - u_m;
                        let quotient = &diff / &q_m_bigint;
                        r_m_coeffs.push(quotient);
                    }

                    res.crt_quotients[party_idx][trbfv_idx][bfv_idx] = r_m_coeffs;
                }

                // Compute decrypted_shares from u_global using BFV decoding formula
                // This matches the circuit's verify_decoding logic:
                // computed_message = (t * u_global * q_inverse_mod_t) mod t, with centering
                let t = BigInt::from(bfv_params.plaintext());
                let q = BigInt::from(ctx.modulus().clone());
                let q_half = &q / BigInt::from(2);

                // Compute q_inverse_mod_t
                use num_integer::Integer;
                let gcd_result = q.extended_gcd(&t);
                let q_inv_mod_t = {
                    let inv = gcd_result.x % &t;
                    if inv < BigInt::zero() { inv + &t } else { inv }
                };

                let mut decoded_shares: Vec<BigInt> = Vec::new();
                for u_global_coeff in u_global.iter() {
                    // t_times_u_q = (t * u_global) mod Q
                    let t_times_u = &t * u_global_coeff;
                    let t_times_u_q = &t_times_u % &q;
                    let t_times_u_q_positive = if t_times_u_q < BigInt::zero() {
                        &t_times_u_q + &q
                    } else {
                        t_times_u_q.clone()
                    };

                    // Check if needs centering
                    let needs_centering = t_times_u_q_positive > q_half;

                    let computed_message = if needs_centering {
                        // centered_positive = Q - t_times_u_q
                        let centered_positive = &q - &t_times_u_q_positive;
                        // result = (q_inv_mod_t * centered_positive) mod t
                        (&q_inv_mod_t * &centered_positive) % &t
                    } else {
                        // product = (q_inv_mod_t * t_times_u_q) mod t
                        let product = (&q_inv_mod_t * &t_times_u_q_positive) % &t;
                        if product == BigInt::zero() {
                            BigInt::zero()
                        } else {
                            &t - &product
                        }
                    };

                    // Ensure positive result
                    let msg = if computed_message < BigInt::zero() {
                        &computed_message + &t
                    } else {
                        computed_message
                    };
                    decoded_shares.push(msg);
                }

                res.decrypted_shares[party_idx][trbfv_idx] = decoded_shares;
            }
        }

        // Compute expected aggregated shares from decrypted_shares
        // For each TRBFV basis l: sum of decrypted_shares[h][l] mod trbfv_qis[l]
        for trbfv_idx in 0..num_trbfv_bases {
            let trbfv_q = BigInt::from(trbfv_params.moduli()[trbfv_idx]);
            let mut aggregated: Vec<BigInt> = vec![BigInt::zero(); n as usize];

            for party_idx in 0..num_honest_parties {
                for (coeff_idx, coeff) in res.decrypted_shares[party_idx][trbfv_idx]
                    .iter()
                    .enumerate()
                {
                    aggregated[coeff_idx] = (&aggregated[coeff_idx] + coeff) % &trbfv_q;
                }
            }

            res.expected_aggregated_shares[trbfv_idx] = aggregated;
        }

        Ok(res)
    }

    /// Convert to standard form (reduce modulo ZKP field)
    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();

        DecBfvNoHomAddVectors {
            honest_c0: reduce_coefficients_4d(&self.honest_c0, zkp_modulus),
            honest_c1: reduce_coefficients_4d(&self.honest_c1, zkp_modulus),
            s: reduce_coefficients(&self.s, zkp_modulus),
            u_i: reduce_coefficients_4d(&self.u_i, zkp_modulus),
            r_1: reduce_coefficients_4d(&self.r_1, zkp_modulus),
            r_2: reduce_coefficients_4d(&self.r_2, zkp_modulus),
            u_global: reduce_coefficients_3d(&self.u_global, zkp_modulus),
            crt_quotients: reduce_coefficients_4d(&self.crt_quotients, zkp_modulus),
            decrypted_shares: reduce_coefficients_3d(&self.decrypted_shares, zkp_modulus),
            expected_aggregated_shares: reduce_coefficients_2d(
                &self.expected_aggregated_shares,
                zkp_modulus,
            ),
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "honest_c0": to_string_4d_vec(&self.honest_c0),
            "honest_c1": to_string_4d_vec(&self.honest_c1),
            "s": to_string_1d_vec(&self.s),
            "u_i": to_string_4d_vec(&self.u_i),
            "r_1": to_string_4d_vec(&self.r_1),
            "r_2": to_string_4d_vec(&self.r_2),
            "u_global": to_string_3d_vec(&self.u_global),
            "crt_quotients": to_string_4d_vec(&self.crt_quotients),
            "decrypted_shares": to_string_3d_vec(&self.decrypted_shares),
            "expected_aggregated_shares": to_string_2d_vec(&self.expected_aggregated_shares),
        })
    }

    /// Verify all circuit constraints in Rust (mirrors Noir circuit logic)
    ///
    /// This function reproduces the verification steps from the Noir circuit:
    /// 1. Verify BFV decryption formula for each ciphertext
    /// 2. Verify CRT reconstruction
    /// 3. Verify decoding from u_global to decrypted_shares
    /// 4. Verify TRBFV share aggregation
    pub fn verify(
        &self,
        bfv_params: &Arc<BfvParameters>,
        trbfv_params: &Arc<BfvParameters>,
    ) -> ZkFheResult<()> {
        let ctx = bfv_params.ctx_at_level(0)?;
        let n = ctx.degree;
        let num_honest_parties = self.honest_c0.len();
        let num_trbfv_bases = trbfv_params.moduli().len();
        let num_bfv_bases = bfv_params.moduli().len();

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); n + 1];
        cyclo[0] = BigInt::from(1u64);
        cyclo[n] = BigInt::from(1u64);
        let cyclo_poly = Polynomial::new(cyclo);

        // Step 1: Verify BFV decryption formula for each ciphertext
        for party_idx in 0..num_honest_parties {
            for trbfv_idx in 0..num_trbfv_bases {
                for bfv_idx in 0..num_bfv_bases {
                    self.verify_decryption_formula(
                        party_idx,
                        trbfv_idx,
                        bfv_idx,
                        ctx,
                        &cyclo_poly,
                    )?;
                }

                // Step 2: Verify CRT reconstruction for this ciphertext
                self.verify_crt_reconstruction(party_idx, trbfv_idx, ctx)?;

                // Step 3: Verify decoding for this ciphertext
                self.verify_decoding(party_idx, trbfv_idx, bfv_params)?;
            }
        }

        // Step 4: Verify TRBFV share aggregation
        self.verify_trbfv_aggregation(trbfv_params)?;

        Ok(())
    }

    /// Verify BFV decryption formula for one ciphertext at one BFV basis
    ///
    /// Checks: u_i(γ) = c_0(γ) + c_1(γ) * s(γ) + r_2(γ) * (γ^N + 1) + r_1(γ) * q'_i
    /// using polynomial evaluation at a random point (Schwartz-Zippel)
    fn verify_decryption_formula(
        &self,
        party_idx: usize,
        trbfv_idx: usize,
        bfv_idx: usize,
        ctx: &Arc<fhe_math::rq::Context>,
        _cyclo_poly: &Polynomial,
    ) -> ZkFheResult<()> {
        let n = ctx.degree;
        let qi = ctx.moduli()[bfv_idx];
        let qi_bigint = BigInt::from(qi);

        // Use a deterministic "random" evaluation point for testing
        // In the real circuit, this comes from Fiat-Shamir
        let gamma = BigInt::from(12345u64);

        // Evaluate polynomials at gamma
        let c0_poly = Polynomial::new(self.honest_c0[party_idx][trbfv_idx][bfv_idx].clone());
        let c1_poly = Polynomial::new(self.honest_c1[party_idx][trbfv_idx][bfv_idx].clone());
        let s_poly = Polynomial::new(self.s.clone());
        let u_i_poly = Polynomial::new(self.u_i[party_idx][trbfv_idx][bfv_idx].clone());
        let r1_poly = Polynomial::new(self.r_1[party_idx][trbfv_idx][bfv_idx].clone());
        let r2_poly = Polynomial::new(self.r_2[party_idx][trbfv_idx][bfv_idx].clone());

        let c0_at_gamma = c0_poly.evaluate(&gamma);
        let c1_at_gamma = c1_poly.evaluate(&gamma);
        let s_at_gamma = s_poly.evaluate(&gamma);
        let u_i_at_gamma = u_i_poly.evaluate(&gamma);
        let r1_at_gamma = r1_poly.evaluate(&gamma);
        let r2_at_gamma = r2_poly.evaluate(&gamma);

        // Cyclotomic polynomial X^N + 1 at gamma
        let gamma_pow_n = gamma.pow(n as u32);
        let cyclo_at_gamma = &gamma_pow_n + BigInt::from(1);

        // Expected: u_i(γ) = c_0(γ) + c_1(γ) * s(γ) + r_2(γ) * (γ^N + 1) + r_1(γ) * q'_i
        let expected_u_at_gamma = &c0_at_gamma
            + &c1_at_gamma * &s_at_gamma
            + &r2_at_gamma * &cyclo_at_gamma
            + &r1_at_gamma * &qi_bigint;

        if expected_u_at_gamma != u_i_at_gamma {
            return Err(ZkFheError::Bfv {
                message: format!(
                    "Decryption formula verification failed at party={}, trbfv={}, bfv={}: \
                    expected u_i(γ)={}, computed={}",
                    party_idx, trbfv_idx, bfv_idx, expected_u_at_gamma, u_i_at_gamma
                ),
            });
        }

        Ok(())
    }

    /// Verify CRT reconstruction for one ciphertext
    /// u_i[l'] + quotient[l'] * q'_l' = u_global (for all l')
    fn verify_crt_reconstruction(
        &self,
        party_idx: usize,
        trbfv_idx: usize,
        ctx: &Arc<fhe_math::rq::Context>,
    ) -> ZkFheResult<()> {
        let n = ctx.degree;
        let num_bfv_bases = ctx.moduli().len();

        for bfv_idx in 0..num_bfv_bases {
            let q_l = BigInt::from(ctx.moduli()[bfv_idx]);

            for coeff_idx in 0..n {
                let u_i_coeff = &self.u_i[party_idx][trbfv_idx][bfv_idx][coeff_idx];
                let quotient_coeff = &self.crt_quotients[party_idx][trbfv_idx][bfv_idx][coeff_idx];
                let u_global_coeff = &self.u_global[party_idx][trbfv_idx][coeff_idx];

                // Verify: u_i + quotient * q'_l = u_global
                let reconstructed = u_i_coeff + quotient_coeff * &q_l;

                if reconstructed != *u_global_coeff {
                    return Err(ZkFheError::Bfv {
                        message: format!(
                            "CRT reconstruction verification failed at party={}, trbfv={}, bfv={}, coeff={}: \
                            u_i={}, quotient={}, q_l={}, reconstructed={}, u_global={}",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            u_i_coeff,
                            quotient_coeff,
                            q_l,
                            reconstructed,
                            u_global_coeff
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    /// Verify BFV decoding: u_global to decrypted_share
    fn verify_decoding(
        &self,
        party_idx: usize,
        trbfv_idx: usize,
        bfv_params: &Arc<BfvParameters>,
    ) -> ZkFheResult<()> {
        let ctx = bfv_params.ctx_at_level(0)?;
        let n = ctx.degree;
        let t = BigInt::from(bfv_params.plaintext());

        // Compute Q = product of all BFV moduli
        let q = BigInt::from(ctx.modulus().clone());
        let q_half = &q / BigInt::from(2);

        // Compute Q^{-1} mod t
        use num_integer::Integer;
        let gcd_result = q.extended_gcd(&t);
        let q_inv_mod_t = {
            let inv = gcd_result.x % &t;
            if inv < BigInt::zero() { inv + &t } else { inv }
        };

        for coeff_idx in 0..n {
            let u_global_coeff = &self.u_global[party_idx][trbfv_idx][coeff_idx];
            let decrypted_coeff = &self.decrypted_shares[party_idx][trbfv_idx][coeff_idx];

            // Compute (t * u_global) mod Q
            let t_times_u = &t * u_global_coeff;
            let t_times_u_q = &t_times_u % &q;
            let t_times_u_q_positive = if t_times_u_q < BigInt::zero() {
                &t_times_u_q + &q
            } else {
                t_times_u_q.clone()
            };

            // Check if centering is needed
            let needs_centering = t_times_u_q_positive > q_half;

            let computed_message = if needs_centering {
                let centered_positive = &q - &t_times_u_q_positive;
                (&q_inv_mod_t * &centered_positive) % &t
            } else {
                let product = (&q_inv_mod_t * &t_times_u_q_positive) % &t;
                if product == BigInt::zero() {
                    BigInt::zero()
                } else {
                    &t - &product
                }
            };

            // Ensure positive
            let computed_message = if computed_message < BigInt::zero() {
                &computed_message + &t
            } else {
                computed_message
            };

            // Verify (only check non-zero coefficients as per Noir circuit)
            if *decrypted_coeff != BigInt::zero() && computed_message != *decrypted_coeff {
                return Err(ZkFheError::Bfv {
                    message: format!(
                        "Decoding verification failed at party={}, trbfv={}, coeff={}: \
                        expected={}, computed={}",
                        party_idx, trbfv_idx, coeff_idx, decrypted_coeff, computed_message
                    ),
                });
            }
        }

        Ok(())
    }

    /// Verify TRBFV share aggregation
    /// For each TRBFV basis l: sum of decrypted_shares[h][l] mod trbfv_qis[l] = expected[l]
    fn verify_trbfv_aggregation(&self, trbfv_params: &Arc<BfvParameters>) -> ZkFheResult<()> {
        let num_honest_parties = self.decrypted_shares.len();
        let num_trbfv_bases = trbfv_params.moduli().len();
        let n = self.decrypted_shares[0][0].len();

        for trbfv_idx in 0..num_trbfv_bases {
            let trbfv_q = BigInt::from(trbfv_params.moduli()[trbfv_idx]);

            for coeff_idx in 0..n {
                // Sum shares from all honest parties
                let mut sum = BigInt::zero();
                for party_idx in 0..num_honest_parties {
                    sum = &sum + &self.decrypted_shares[party_idx][trbfv_idx][coeff_idx];
                }

                // Reduce mod TRBFV modulus
                let sum_reduced = &sum % &trbfv_q;
                let sum_reduced = if sum_reduced < BigInt::zero() {
                    &sum_reduced + &trbfv_q
                } else {
                    sum_reduced
                };

                // Verify against expected
                let expected = &self.expected_aggregated_shares[trbfv_idx][coeff_idx];
                if sum_reduced != *expected {
                    return Err(ZkFheError::Bfv {
                        message: format!(
                            "TRBFV aggregation verification failed at trbfv={}, coeff={}: \
                            sum_reduced={}, expected={}",
                            trbfv_idx, coeff_idx, sum_reduced, expected
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

/// Reduce 4D coefficients modulo zkp_modulus
fn reduce_coefficients_4d(
    coeffs: &[Vec<Vec<Vec<BigInt>>>],
    zkp_modulus: &BigInt,
) -> Vec<Vec<Vec<Vec<BigInt>>>> {
    coeffs
        .iter()
        .map(|d1| reduce_coefficients_3d(d1, zkp_modulus))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_decryption_no_hom_add;
    use shared::utils::{test_parameters_bfv, test_parameters_trbfv};

    #[test]
    fn test_vector_computation() {
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();

        let data = generate_sample_decryption_no_hom_add(&bfv_params, &trbfv_params, None).unwrap();

        let vectors = DecBfvNoHomAddVectors::compute(
            &data.honest_ciphertexts,
            &data.secret_key,
            &bfv_params,
            &trbfv_params,
        )
        .unwrap();

        // Verify structure
        assert_eq!(vectors.honest_c0.len(), data.num_honest_parties);
        assert_eq!(vectors.honest_c0[0].len(), data.num_trbfv_bases);
        assert_eq!(vectors.honest_c0[0][0].len(), data.num_bfv_bases);
        assert_eq!(vectors.decrypted_shares.len(), data.num_honest_parties);
        assert_eq!(
            vectors.expected_aggregated_shares.len(),
            data.num_trbfv_bases
        );
    }

    #[test]
    fn test_standard_form() {
        let vecs = DecBfvNoHomAddVectors::new(5, 2, 1, 512);
        let std_form = vecs.standard_form();

        let p = shared::constants::get_zkp_modulus();
        assert!(std_form.s.iter().all(|x| x < &p));
        assert!(
            std_form
                .expected_aggregated_shares
                .iter()
                .all(|row| row.iter().all(|x| x < &p))
        );
    }

    #[test]
    fn test_verify_circuit_constraints() {
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();

        let data = generate_sample_decryption_no_hom_add(&bfv_params, &trbfv_params, None).unwrap();

        let vectors = DecBfvNoHomAddVectors::compute(
            &data.honest_ciphertexts,
            &data.secret_key,
            &bfv_params,
            &trbfv_params,
        )
        .unwrap();

        // Verify all circuit constraints pass
        let result = vectors.verify(&bfv_params, &trbfv_params);
        assert!(
            result.is_ok(),
            "Circuit verification should pass: {:?}",
            result.err()
        );
    }
}
