//! Input validation vectors for BFV decryption zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct BFV decryption in zero-knowledge.

use bigint_poly::*;
use fhe::bfv::{BfvParameters, Ciphertext, Plaintext, SecretKey};
use fhe_math::rq::{Poly, Representation, traits::TryConvertFrom};
use itertools::izip;
use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use std::sync::Arc;

use ark_bn254::Fr as Field;
use ark_ff::{BigInteger, PrimeField};

use shared::errors::{ZkFheError, ZkFheResult};
use shared::packing::flatten;
use shared::utils::{compute_safe, to_string_1d_vec, to_string_2d_vec};

/// Set of vectors for input validation of BFV decryption
/// Structure matches bfv_dec.nr circuit:
/// - honest_c0[H][L][L_PRIME][N]: Ciphertext component 0 for each party, TRBFV basis, BFV basis
/// - honest_c1[H][L][L_PRIME][N]: Ciphertext component 1
/// - sum_c0[L][L_PRIME][N]: Aggregated ciphertext component 0
/// - sum_c1[L][L_PRIME][N]: Aggregated ciphertext component 1
/// - s[N]: BFV secret key (single polynomial)
/// - u_i[L][L_PRIME][N]: Per-TRBFV-basis per-BFV-basis decryption result
/// - r_1[L][L_PRIME][2N-1]: Modulus quotient polynomials
/// - r_2[L][L_PRIME][N-1]: Cyclotomic quotient polynomials
/// - u_global[L][N]: CRT reconstructed polynomials (one per TRBFV basis)
/// - crt_quotients[L][L_PRIME][N]: CRT lifting quotients
/// - message[L][N]: Message polynomials (one per TRBFV basis, public input)
/// - expected_sk_commitment: Commitment to BFV secret key (from BFV public key circuit)
#[derive(Clone, Debug)]
pub struct DecBfvVectors {
    pub honest_c0: Vec<Vec<Vec<Vec<BigInt>>>>, // [H][L][L_PRIME][N]
    pub honest_c1: Vec<Vec<Vec<Vec<BigInt>>>>, // [H][L][L_PRIME][N]
    pub sum_c0: Vec<Vec<Vec<BigInt>>>,         // [L][L_PRIME][N] - Sum of honest ciphertexts
    pub sum_c1: Vec<Vec<Vec<BigInt>>>,         // [L][L_PRIME][N]
    pub s: Vec<BigInt>,                        // [N] - Single secret key polynomial
    pub u_i: Vec<Vec<Vec<BigInt>>>,            // [L][L_PRIME][N]
    pub r_1: Vec<Vec<Vec<BigInt>>>,            // [L][L_PRIME][2N-1]
    pub r_2: Vec<Vec<Vec<BigInt>>>,            // [L][L_PRIME][N-1]
    pub u_global: Vec<Vec<BigInt>>,            // [L][N]
    pub crt_quotients: Vec<Vec<Vec<BigInt>>>,  // [L][L_PRIME][N]
    pub message: Vec<Vec<BigInt>>,             // [L][N] - One per TRBFV basis
    pub expected_sk_commitment: BigInt,
}

impl DecBfvVectors {
    /// Create a new `DecBfvVectors` with the given dimensions
    pub fn new(
        num_honest_parties: usize,
        num_trbfv_bases: usize,
        num_bfv_bases: usize,
        degree: usize,
    ) -> Self {
        DecBfvVectors {
            honest_c0: vec![
                vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases];
                num_honest_parties
            ],
            honest_c1: vec![
                vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases];
                num_honest_parties
            ],
            sum_c0: vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases],
            sum_c1: vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases],
            s: vec![BigInt::zero(); degree],
            u_i: vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases],
            r_1: vec![vec![vec![BigInt::zero(); 2 * degree - 1]; num_bfv_bases]; num_trbfv_bases],
            r_2: vec![vec![vec![BigInt::zero(); degree - 1]; num_bfv_bases]; num_trbfv_bases],
            u_global: vec![vec![BigInt::zero(); degree]; num_trbfv_bases],
            crt_quotients: vec![vec![vec![BigInt::zero(); degree]; num_bfv_bases]; num_trbfv_bases],
            message: vec![vec![BigInt::zero(); degree]; num_trbfv_bases],
            expected_sk_commitment: BigInt::zero(),
        }
    }

    /// Compute a commitment to the secret key polynomial by flattening it and hashing.
    /// This matches the Noir `compute_sk_commitment` function exactly.
    fn compute_sk_commitment(sk: &[BigInt], bit_sk: u32) -> BigInt {
        // Step 1: Flatten sk (matches sk_payload in Noir)
        let mut inputs: Vec<Field> = Vec::new();
        inputs = flatten(inputs, &[sk.to_vec()], bit_sk);

        // Step 2: Hash using SafeSponge (matches compute_sk_commitment in Noir)
        // Domain separator - "PVSS_sk_comm" (must match BFV public key circuit)
        let domain_separator: [u8; 64] = [
            0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];

        // IO Pattern: ABSORB(input_size), SQUEEZE(1)
        let input_size = inputs.len() as u32;
        let io_pattern = [0x80000000 | input_size, 0x00000001];

        let commitment = compute_safe(domain_separator, inputs, io_pattern);

        // Convert Field to BigInt
        let commitment_field = commitment[0];
        let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
        BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
    }

    /// Create the centered validation vectors for BFV decryption proof.
    ///
    /// This computes all witness polynomials needed to prove:
    /// 1. Ciphertext aggregation: H honest ciphertexts sum correctly
    /// 2. Decryption formula: u_i = c_0i + c_1i * s + r_2_i * (X^N + 1) + r_1_i * q_i
    /// 3. CRT reconstruction: u_i + quotient_i * q_i = u_global
    /// 4. Correct decoding: |u_global - delta * m| < delta/2
    ///
    /// # Arguments
    ///
    /// * `honest_cts` - H*L ciphertexts [party_idx][trbfv_basis]
    /// * `sk` - BFV secret key used for decryption
    /// * `bfv_params` - BFV parameters
    /// * `trbfv_params` - TRBFV parameters
    /// * `bit_sk` - Bit width for secret key (for commitment computation)
    /// * `decrypted_message` - The decrypted plaintext message (from sample data)
    pub fn compute(
        honest_cts: &[Vec<Ciphertext>],
        sk: &SecretKey,
        bfv_params: &Arc<BfvParameters>,
        trbfv_params: &Arc<BfvParameters>,
        bit_sk: u32,
        _decrypted_message: &Plaintext,
    ) -> ZkFheResult<DecBfvVectors> {
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
        let mut res = DecBfvVectors::new(
            num_honest_parties,
            num_trbfv_bases,
            num_bfv_bases,
            n as usize,
        );

        // Extract secret key coefficients (centered) - single polynomial s
        let sk_coeffs = sk_poly.coefficients();
        let sk_row = sk_coeffs.row(0);
        let mut s: Vec<BigInt> = sk_row.iter().rev().map(|&x| BigInt::from(x)).collect();
        let qi_bigint = BigInt::from(ctx.moduli_operators()[0].modulus());
        reduce_and_center_coefficients_mut(&mut s, &qi_bigint);
        res.s = s.clone();

        // Compute expected_sk_commitment
        res.expected_sk_commitment = Self::compute_sk_commitment(&res.s, bit_sk);

        // Step 1: Extract all honest ciphertexts and aggregate per TRBFV basis
        // For each TRBFV basis, sum all H honest ciphertexts
        let mut aggregated_polys: Vec<(usize, Poly, Poly)> = Vec::new();

        for trbfv_idx in 0..num_trbfv_bases {
            // Aggregate all honest ciphertexts for this TRBFV basis
            let mut sum_ct0: Option<Poly> = None;
            let mut sum_ct1: Option<Poly> = None;

            for party_idx in 0..num_honest_parties {
                if trbfv_idx < honest_cts[party_idx].len() {
                    let ct = &honest_cts[party_idx][trbfv_idx];
                    let mut ct0 = ct.c[0].clone();
                    let mut ct1 = ct.c[1].clone();

                    // Extract and store honest ciphertext components
                    ct0.change_representation(Representation::PowerBasis);
                    ct1.change_representation(Representation::PowerBasis);

                    let ct0_coeffs = ct0.coefficients();
                    let ct1_coeffs = ct1.coefficients();

                    // Store honest ciphertexts per BFV basis
                    for (bfv_idx, _qi) in ctx.moduli_operators().iter().enumerate() {
                        let ct0_row = ct0_coeffs.row(bfv_idx);
                        let ct1_row = ct1_coeffs.row(bfv_idx);

                        // Keep in [0, q_i) - do NOT center to avoid u128 overflow in circuit's reduce_mod
                        let ct0i: Vec<BigInt> =
                            ct0_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                        let ct1i: Vec<BigInt> =
                            ct1_row.iter().rev().map(|&x| BigInt::from(x)).collect();

                        res.honest_c0[party_idx][trbfv_idx][bfv_idx] = ct0i;
                        res.honest_c1[party_idx][trbfv_idx][bfv_idx] = ct1i;
                    }

                    // Aggregate ciphertexts
                    if sum_ct0.is_none() {
                        sum_ct0 = Some(ct0);
                        sum_ct1 = Some(ct1);
                    } else {
                        sum_ct0 = Some(&sum_ct0.unwrap() + &ct0);
                        sum_ct1 = Some(&sum_ct1.unwrap() + &ct1);
                    }
                }
            }

            // Store aggregated polynomials for decryption (with actual TRBFV basis index)
            if let (Some(sum_ct0_poly), Some(sum_ct1_poly)) = (sum_ct0, sum_ct1) {
                aggregated_polys.push((trbfv_idx, sum_ct0_poly, sum_ct1_poly));
            }
        }

        // Step 2: Decrypt aggregated ciphertexts per TRBFV basis
        // Track which TRBFV bases we actually processed (have ciphertexts)
        let mut processed_trbfv_bases = std::collections::HashSet::new();

        // Validate that we have aggregated ciphertexts for all TRBFV bases
        if aggregated_polys.len() != num_trbfv_bases {
            return Err(ZkFheError::Bfv {
                message: format!(
                    "Expected {} TRBFV bases but only {} have ciphertexts. All TRBFV bases must have ciphertexts.",
                    num_trbfv_bases,
                    aggregated_polys.len()
                ),
            });
        }

        // For each TRBFV basis, decrypt the aggregated ciphertext
        for &(trbfv_idx, ref sum_ct0_poly, ref sum_ct1_poly) in aggregated_polys.iter() {
            processed_trbfv_bases.insert(trbfv_idx);
            // Extract aggregated ciphertext components
            let mut sum_ct0 = sum_ct0_poly.clone();
            let mut sum_ct1 = sum_ct1_poly.clone();
            sum_ct0.change_representation(Representation::PowerBasis);
            sum_ct1.change_representation(Representation::PowerBasis);

            // Compute u_rns = c_0 + c_1 * s (intermediate decryption before scaling)
            let mut s_ntt = sk_poly.clone();
            s_ntt.change_representation(Representation::Ntt);
            let mut sum_ct1_ntt = sum_ct1.clone();
            sum_ct1_ntt.change_representation(Representation::Ntt);
            let mut c1_times_s = &sum_ct1_ntt * &s_ntt;
            c1_times_s.change_representation(Representation::PowerBasis);
            let u_rns = &sum_ct0 + &c1_times_s;

            let sum_ct0_coeffs = sum_ct0.coefficients();
            let sum_ct1_coeffs = sum_ct1.coefficients();
            let _u_coeffs = u_rns.coefficients();

            // Store aggregated ciphertext components
            for (bfv_idx, _qi) in ctx.moduli_operators().iter().enumerate() {
                let sum_ct0_row = sum_ct0_coeffs.row(bfv_idx);
                let sum_ct1_row = sum_ct1_coeffs.row(bfv_idx);

                // Keep in [0, q_i) - do NOT center to avoid u128 overflow in circuit's reduce_mod
                let sum_ct0i: Vec<BigInt> =
                    sum_ct0_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                let sum_ct1i: Vec<BigInt> =
                    sum_ct1_row.iter().rev().map(|&x| BigInt::from(x)).collect();

                res.sum_c0[trbfv_idx][bfv_idx] = sum_ct0i;
                res.sum_c1[trbfv_idx][bfv_idx] = sum_ct1i;
            }

            // Process each BFV basis for this TRBFV basis
            let sum_ct0_coeffs = sum_ct0.coefficients();
            let sum_ct1_coeffs = sum_ct1.coefficients();
            let u_coeffs = u_rns.coefficients();

            let sum_ct0_coeffs_rows = sum_ct0_coeffs.rows();
            let sum_ct1_coeffs_rows = sum_ct1_coeffs.rows();
            let u_coeffs_rows = u_coeffs.rows();

            // Perform the main computation logic in parallel for each BFV basis
            let results: Vec<_> = izip!(
                ctx.moduli_operators(),
                sum_ct0_coeffs_rows,
                sum_ct1_coeffs_rows,
                u_coeffs_rows,
            )
            .enumerate()
            .par_bridge()
            .map(|(bfv_idx, (qi, sum_ct0_row, sum_ct1_row, u_row))| {
                let qi_bigint = BigInt::from(qi.modulus());

                // Convert to BigInt vectors (reversed for polynomial representation)
                let sum_ct0i: Vec<BigInt> =
                    sum_ct0_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                let sum_ct1i: Vec<BigInt> =
                    sum_ct1_row.iter().rev().map(|&x| BigInt::from(x)).collect();
                let mut ui: Vec<BigInt> = u_row.iter().rev().map(|&x| BigInt::from(x)).collect();

                // Center ui (sum_ct0i and sum_ct1i are already stored in res.sum_c0/sum_c1)
                reduce_and_center_coefficients_mut(&mut ui, &qi_bigint);

                // Calculate u_i_hat = sum_c_0i + sum_c_1i * s
                // Note: sum_ct0i, sum_ct1i are in [0, q_i), s is centered
                let ui_hat = {
                    let sum_ct0i_poly = Polynomial::new(sum_ct0i.clone());
                    let sum_ct1i_poly = Polynomial::new(sum_ct1i.clone());
                    let s_poly = Polynomial::new(res.s.clone());
                    let ct1i_times_s = sum_ct1i_poly.mul(&s_poly);
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
                let r2i_poly_check = Polynomial::new(r2i.clone());
                let r2i_times_cyclo = r2i_poly_check.mul(&cyclo_poly).coefficients().to_vec();
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
                let r1i_poly_check = Polynomial::new(r1i.clone());
                let r1i_times_qi = r1i_poly_check
                    .scalar_mul(&qi_bigint)
                    .coefficients()
                    .to_vec();
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
                assert_eq!(&ui, &ui_calculated);

                (bfv_idx, ui, r1i, r2i)
            })
            .collect();

            // Store results for this TRBFV basis
            for (bfv_idx, ui, r1i, r2i) in results {
                res.u_i[trbfv_idx][bfv_idx] = ui;
                res.r_1[trbfv_idx][bfv_idx] = r1i;
                res.r_2[trbfv_idx][bfv_idx] = r2i;
            }

            // Step 3: CRT reconstruction for this TRBFV basis
            // Collect residues from all BFV bases for CRT reconstruction
            let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();
            for bfv_idx in 0..num_bfv_bases {
                let q_m = ctx.moduli()[bfv_idx];
                let q_m_bigint = BigInt::from(q_m);
                let mut u_m: Vec<u64> = Vec::new();

                for coeff in res.u_i[trbfv_idx][bfv_idx].iter() {
                    // Reduce coefficient modulo q_m and ensure it's positive
                    let mut val = coeff % &q_m_bigint;
                    if val < BigInt::zero() {
                        val += &q_m_bigint;
                    }
                    // Convert to u64 (should fit since it's mod q_m)
                    u_m.push(val.to_u64().expect("Coefficient should fit in u64"));
                }
                u_per_modulus.push(u_m);
            }

            // CRT reconstruction using RnsContext
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

            // Ensure u_global has the correct length
            assert_eq!(
                u_global.len(),
                n as usize,
                "u_global length mismatch: expected {}, got {}",
                n,
                u_global.len()
            );

            res.u_global[trbfv_idx] = u_global.clone();

            // Compute CRT quotients: (u_global - u_i) / q_i for each BFV basis
            for bfv_idx in 0..num_bfv_bases {
                let q_m = ctx.moduli()[bfv_idx];
                let q_m_bigint = BigInt::from(q_m);
                let mut r_m_coeffs: Vec<BigInt> = Vec::new();

                for (coeff_idx, u_global_val) in u_global.iter().enumerate().take(n as usize) {
                    let u_m = &res.u_i[trbfv_idx][bfv_idx][coeff_idx];
                    let diff = u_global_val - u_m;
                    let quotient = &diff / &q_m_bigint;
                    r_m_coeffs.push(quotient);
                }

                res.crt_quotients[trbfv_idx][bfv_idx] = r_m_coeffs;
            }
        }

        // Step 4: Compute decoded message from u_global using BFV decoding formula
        // This matches the circuit's compute_decoded_message function
        let t = BigInt::from(bfv_params.plaintext());

        // Compute Q as product of all BFV CRT moduli
        let mut q_modulus = BigInt::from(1u64);
        for bfv_idx in 0..num_bfv_bases {
            q_modulus *= BigInt::from(ctx.moduli()[bfv_idx]);
        }
        let q_half = &q_modulus / BigInt::from(2u64);

        // Compute Q^{-1} mod t
        use num_integer::Integer;
        let gcd_result = q_modulus.extended_gcd(&t);
        let q_inv_mod_t = {
            let inv = gcd_result.x % &t;
            if inv < BigInt::zero() { inv + &t } else { inv }
        };

        // For each TRBFV basis, compute message from u_global
        // All TRBFV bases should have been processed (validated above)
        for trbfv_idx in 0..num_trbfv_bases {
            // Validate that this TRBFV basis was processed
            if !processed_trbfv_bases.contains(&trbfv_idx) {
                return Err(ZkFheError::Bfv {
                    message: format!(
                        "TRBFV basis {} was not processed. All bases must have ciphertexts.",
                        trbfv_idx
                    ),
                });
            }

            for coeff_idx in 0..n as usize {
                let u_global_coeff = &res.u_global[trbfv_idx][coeff_idx];

                // Compute (t * u_global) mod Q
                let t_times_u = &t * u_global_coeff;
                let t_times_u_q = &t_times_u % &q_modulus;
                let t_times_u_q_positive = if t_times_u_q < BigInt::zero() {
                    &t_times_u_q + &q_modulus
                } else {
                    t_times_u_q.clone()
                };

                // Check if needs centering
                let needs_centering = t_times_u_q_positive > q_half;

                let computed_coeff = if needs_centering {
                    // centered_positive = Q - t_times_u_q
                    let centered_positive = &q_modulus - &t_times_u_q_positive;
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
                let msg = if computed_coeff < BigInt::zero() {
                    &computed_coeff + &t
                } else {
                    computed_coeff
                };

                res.message[trbfv_idx][coeff_idx] = msg;
            }
        }

        Ok(res)
    }

    // Verify decoding in Rust (mimics the circuit's verify_direct_decoding function)
    // This helps catch issues before running the circuit
    // Note: This function is not currently used but kept for potential future use
    // The new structure has u_global and message as Vec<Vec<BigInt>> (per TRBFV basis)
    #[allow(dead_code)]
    fn verify_decoding_rust(
        &self,
        _ctx: &Arc<fhe_math::rq::Context>,
        _params: &Arc<BfvParameters>,
    ) -> ZkFheResult<()> {
        // TODO: Implement proper decoding verification for new structure
        // The new structure has u_global and message as Vec<Vec<BigInt>> (per TRBFV basis)
        // This needs to be updated to handle the per-TRBFV-basis structure
        Ok(())
    }
}

impl DecBfvVectors {
    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();

        // Helper function to reduce 4D vectors
        fn reduce_coefficients_4d(
            vec: &[Vec<Vec<Vec<BigInt>>>],
            zkp_modulus: &BigInt,
        ) -> Vec<Vec<Vec<Vec<BigInt>>>> {
            vec.iter()
                .map(|d1| {
                    d1.iter()
                        .map(|d2| reduce_coefficients_2d(d2, zkp_modulus))
                        .collect()
                })
                .collect()
        }

        // Helper function to reduce 3D vectors
        fn reduce_coefficients_3d(
            vec: &[Vec<Vec<BigInt>>],
            zkp_modulus: &BigInt,
        ) -> Vec<Vec<Vec<BigInt>>> {
            vec.iter()
                .map(|d1| reduce_coefficients_2d(d1, zkp_modulus))
                .collect()
        }

        let result = DecBfvVectors {
            honest_c0: reduce_coefficients_4d(&self.honest_c0, zkp_modulus),
            honest_c1: reduce_coefficients_4d(&self.honest_c1, zkp_modulus),
            sum_c0: reduce_coefficients_3d(&self.sum_c0, zkp_modulus),
            sum_c1: reduce_coefficients_3d(&self.sum_c1, zkp_modulus),
            s: reduce_coefficients(&self.s, zkp_modulus),
            u_i: reduce_coefficients_3d(&self.u_i, zkp_modulus),
            r_1: reduce_coefficients_3d(&self.r_1, zkp_modulus),
            r_2: reduce_coefficients_3d(&self.r_2, zkp_modulus),
            u_global: reduce_coefficients_2d(&self.u_global, zkp_modulus),
            crt_quotients: reduce_coefficients_3d(&self.crt_quotients, zkp_modulus),
            message: reduce_coefficients_2d(&self.message, zkp_modulus),
            expected_sk_commitment: {
                let mut reduced = self.expected_sk_commitment.clone() % zkp_modulus;
                if reduced < BigInt::zero() {
                    reduced += zkp_modulus;
                }
                reduced
            },
        };

        // Validate original values (before reduction) for u128 constraints
        // Values that must be small for reduce_mod operations should be checked before reduction
        self.validate_small_values();

        // Validate reduced values are in [0, zkp_modulus) range
        result.validate_for_circuit(zkp_modulus);

        result
    }

    pub fn to_json(&self) -> serde_json::Value {
        use shared::utils::{to_string_3d_vec, to_string_4d_vec};
        json!({
            "honest_c0": to_string_4d_vec(&self.honest_c0),
            "honest_c1": to_string_4d_vec(&self.honest_c1),
            "sum_c0": to_string_3d_vec(&self.sum_c0),
            "sum_c1": to_string_3d_vec(&self.sum_c1),
            "s": to_string_1d_vec(&self.s),
            "u_i": to_string_3d_vec(&self.u_i),
            "r_1": to_string_3d_vec(&self.r_1),
            "r_2": to_string_3d_vec(&self.r_2),
            "u_global": to_string_2d_vec(&self.u_global),
            "crt_quotients": to_string_3d_vec(&self.crt_quotients),
            "message": to_string_2d_vec(&self.message),
            "expected_sk_commitment": self.expected_sk_commitment.to_string(),
        })
    }

    /// Validates that small values (used in reduce_mod) are < 2^128 BEFORE reduction
    /// This should be called before standard_form() to check the original values
    fn validate_small_values(&self) {
        let u128_max = BigInt::from(u128::MAX);

        // Check honest_c0 - must be small (< 2^128) since they're ciphertext coefficients in [0, q_i)
        // Structure: [H][L][L_PRIME][N]
        for (party_idx, party_c0) in self.honest_c0.iter().enumerate() {
            for (trbfv_idx, trbfv_c0) in party_c0.iter().enumerate() {
                for (bfv_idx, bfv_c0) in trbfv_c0.iter().enumerate() {
                    for (coeff_idx, coeff) in bfv_c0.iter().enumerate() {
                        assert!(
                            coeff <= &u128_max,
                            "honest_c0[{}][{}][{}][{}] = {} > u128::MAX = {} (before reduction)",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            coeff,
                            u128_max
                        );
                    }
                }
            }
        }

        // Check honest_c1 - must be small (< 2^128) since they're ciphertext coefficients in [0, q_i)
        // Structure: [H][L][L_PRIME][N]
        for (party_idx, party_c1) in self.honest_c1.iter().enumerate() {
            for (trbfv_idx, trbfv_c1) in party_c1.iter().enumerate() {
                for (bfv_idx, bfv_c1) in trbfv_c1.iter().enumerate() {
                    for (coeff_idx, coeff) in bfv_c1.iter().enumerate() {
                        assert!(
                            coeff <= &u128_max,
                            "honest_c1[{}][{}][{}][{}] = {} > u128::MAX = {} (before reduction)",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            coeff,
                            u128_max
                        );
                    }
                }
            }
        }

        // Check sum_c0 - must be small (< 2^128) since it's a ciphertext coefficient in [0, q_i)
        // Structure: [L][L_PRIME][N]
        for (trbfv_idx, trbfv_c0) in self.sum_c0.iter().enumerate() {
            for (bfv_idx, bfv_c0) in trbfv_c0.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_c0.iter().enumerate() {
                    assert!(
                        coeff <= &u128_max,
                        "sum_c0[{}][{}][{}] = {} > u128::MAX = {} (before reduction)",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        u128_max
                    );
                }
            }
        }

        // Check sum_c1 - must be small (< 2^128) since it's a ciphertext coefficient in [0, q_i)
        // Structure: [L][L_PRIME][N]
        for (trbfv_idx, trbfv_c1) in self.sum_c1.iter().enumerate() {
            for (bfv_idx, bfv_c1) in trbfv_c1.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_c1.iter().enumerate() {
                    assert!(
                        coeff <= &u128_max,
                        "sum_c1[{}][{}][{}] = {} > u128::MAX = {} (before reduction)",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        u128_max
                    );
                }
            }
        }

        // Check message - must be small (< 2^128)
        // Structure: [L][N]
        for (trbfv_idx, trbfv_msg) in self.message.iter().enumerate() {
            for (coeff_idx, coeff) in trbfv_msg.iter().enumerate() {
                assert!(
                    coeff <= &u128_max,
                    "message[{}][{}] = {} > u128::MAX = {} (before reduction)",
                    trbfv_idx,
                    coeff_idx,
                    coeff,
                    u128_max
                );
            }
        }
    }

    /// Validates that all values meet the requirements for the circuit AFTER reduction:
    /// 1. All values are in [0, zkp_modulus) range
    /// 2. Values that can be > 2^128 (only used in Field arithmetic):
    ///    - s: range_check_2bounds, eval
    ///    - u_i: range_check_2bounds, eval, add (CRT)
    ///    - r_1: eval (quotient polynomial)
    ///    - r_2: range_check_2bounds, eval (quotient polynomial)
    ///    - u_global: add, mul, equality (CRT reconstruction)
    ///    - crt_quotients: mul, add, equality (CRT verification)
    fn validate_for_circuit(&self, zkp_modulus: &BigInt) {
        // Check s (secret key) - can be large (> 2^128) after reduce_coefficients
        // Structure: [N] - single polynomial
        for (coeff_idx, coeff) in self.s.iter().enumerate() {
            assert!(
                coeff >= &BigInt::zero(),
                "s[{}] = {} is negative",
                coeff_idx,
                coeff
            );
            assert!(
                coeff < zkp_modulus,
                "s[{}] = {} >= zkp_modulus = {}",
                coeff_idx,
                coeff,
                zkp_modulus
            );
        }

        // Check u_i - can be large (> 2^128) after reduce_coefficients_3d
        // Structure: [L][L_PRIME][N]
        for (trbfv_idx, trbfv_u_i) in self.u_i.iter().enumerate() {
            for (bfv_idx, bfv_u_i) in trbfv_u_i.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_u_i.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "u_i[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "u_i[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check r_1 - can be large (> 2^128) since it's a quotient by q_i
        // Structure: [L][L_PRIME][2N-1]
        for (trbfv_idx, trbfv_r1) in self.r_1.iter().enumerate() {
            for (bfv_idx, bfv_r1) in trbfv_r1.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_r1.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "r_1[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "r_1[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check r_2 - can be large (> 2^128) after reduce_coefficients_3d
        // Structure: [L][L_PRIME][N-1]
        for (trbfv_idx, trbfv_r2) in self.r_2.iter().enumerate() {
            for (bfv_idx, bfv_r2) in trbfv_r2.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_r2.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "r_2[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "r_2[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check u_global - can be large (> 2^128) since it's CRT reconstruction
        // Structure: [L][N]
        for (trbfv_idx, trbfv_u_global) in self.u_global.iter().enumerate() {
            for (coeff_idx, coeff) in trbfv_u_global.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "u_global[{}][{}] = {} is negative",
                    trbfv_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "u_global[{}][{}] = {} >= zkp_modulus = {}",
                    trbfv_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check crt_quotients - can be large (> 2^128) since they're derived from u_global
        // Structure: [L][L_PRIME][N]
        for (trbfv_idx, trbfv_crt) in self.crt_quotients.iter().enumerate() {
            for (bfv_idx, bfv_crt) in trbfv_crt.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_crt.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "crt_quotients[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "crt_quotients[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check honest_c0, honest_c1, sum_c0, sum_c1 - after reduction they can be large
        // but should still be in [0, zkp_modulus) range
        // Structure: [H][L][L_PRIME][N] for honest_c0/c1, [L][L_PRIME][N] for sum_c0/c1
        for (party_idx, party_c0) in self.honest_c0.iter().enumerate() {
            for (trbfv_idx, trbfv_c0) in party_c0.iter().enumerate() {
                for (bfv_idx, bfv_c0) in trbfv_c0.iter().enumerate() {
                    for (coeff_idx, coeff) in bfv_c0.iter().enumerate() {
                        assert!(
                            coeff >= &BigInt::zero(),
                            "honest_c0[{}][{}][{}][{}] = {} is negative",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            coeff
                        );
                        assert!(
                            coeff < zkp_modulus,
                            "honest_c0[{}][{}][{}][{}] = {} >= zkp_modulus = {}",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            coeff,
                            zkp_modulus
                        );
                    }
                }
            }
        }

        for (party_idx, party_c1) in self.honest_c1.iter().enumerate() {
            for (trbfv_idx, trbfv_c1) in party_c1.iter().enumerate() {
                for (bfv_idx, bfv_c1) in trbfv_c1.iter().enumerate() {
                    for (coeff_idx, coeff) in bfv_c1.iter().enumerate() {
                        assert!(
                            coeff >= &BigInt::zero(),
                            "honest_c1[{}][{}][{}][{}] = {} is negative",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            coeff
                        );
                        assert!(
                            coeff < zkp_modulus,
                            "honest_c1[{}][{}][{}][{}] = {} >= zkp_modulus = {}",
                            party_idx,
                            trbfv_idx,
                            bfv_idx,
                            coeff_idx,
                            coeff,
                            zkp_modulus
                        );
                    }
                }
            }
        }

        for (trbfv_idx, trbfv_c0) in self.sum_c0.iter().enumerate() {
            for (bfv_idx, bfv_c0) in trbfv_c0.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_c0.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "sum_c0[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "sum_c0[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        for (trbfv_idx, trbfv_c1) in self.sum_c1.iter().enumerate() {
            for (bfv_idx, bfv_c1) in trbfv_c1.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_c1.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "sum_c1[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "sum_c1[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check message - after reduction it can be large but should be in [0, zkp_modulus)
        // Structure: [L][N]
        for (trbfv_idx, trbfv_msg) in self.message.iter().enumerate() {
            for (coeff_idx, coeff) in trbfv_msg.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "message[{}][{}] = {} is negative",
                    trbfv_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "message[{}][{}] = {} >= zkp_modulus = {}",
                    trbfv_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check s (secret key) - can be large (> 2^128) after reduce_coefficients
        // Structure: [N] - single polynomial
        for (coeff_idx, coeff) in self.s.iter().enumerate() {
            assert!(
                coeff >= &BigInt::zero(),
                "s[{}] = {} is negative",
                coeff_idx,
                coeff
            );
            assert!(
                coeff < zkp_modulus,
                "s[{}] = {} >= zkp_modulus = {}",
                coeff_idx,
                coeff,
                zkp_modulus
            );
        }

        // Check u_i - can be large (> 2^128) after reduce_coefficients_3d
        // Structure: [L][L_PRIME][N]
        for (trbfv_idx, trbfv_u_i) in self.u_i.iter().enumerate() {
            for (bfv_idx, bfv_u_i) in trbfv_u_i.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_u_i.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "u_i[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "u_i[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check r_1 - can be large (> 2^128) since it's a quotient by q_i
        // Structure: [L][L_PRIME][2N-1]
        for (trbfv_idx, trbfv_r1) in self.r_1.iter().enumerate() {
            for (bfv_idx, bfv_r1) in trbfv_r1.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_r1.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "r_1[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "r_1[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check r_2 - can be large (> 2^128) after reduce_coefficients_3d
        // Structure: [L][L_PRIME][N-1]
        for (trbfv_idx, trbfv_r2) in self.r_2.iter().enumerate() {
            for (bfv_idx, bfv_r2) in trbfv_r2.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_r2.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "r_2[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "r_2[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check u_global - can be large (> 2^128) since it's CRT reconstruction
        // Structure: [L][N]
        for (trbfv_idx, trbfv_u_global) in self.u_global.iter().enumerate() {
            for (coeff_idx, coeff) in trbfv_u_global.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "u_global[{}][{}] = {} is negative",
                    trbfv_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "u_global[{}][{}] = {} >= zkp_modulus = {}",
                    trbfv_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
            }
        }

        // Check crt_quotients - can be large (> 2^128) since they're derived from u_global
        // Structure: [L][L_PRIME][N]
        for (trbfv_idx, trbfv_crt) in self.crt_quotients.iter().enumerate() {
            for (bfv_idx, bfv_crt) in trbfv_crt.iter().enumerate() {
                for (coeff_idx, coeff) in bfv_crt.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "crt_quotients[{}][{}][{}] = {} is negative",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "crt_quotients[{}][{}][{}] = {} >= zkp_modulus = {}",
                        trbfv_idx,
                        bfv_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                }
            }
        }

        // Check message - must be small (< 2^128)
        // Structure: [L][N]
        for (trbfv_idx, trbfv_msg) in self.message.iter().enumerate() {
            let u128_max = BigInt::from(u128::MAX);

            for (coeff_idx, coeff) in trbfv_msg.iter().enumerate() {
                assert!(
                    coeff >= &BigInt::zero(),
                    "message[{}][{}] = {} is negative",
                    trbfv_idx,
                    coeff_idx,
                    coeff
                );
                assert!(
                    coeff < zkp_modulus,
                    "message[{}][{}] = {} >= zkp_modulus = {}",
                    trbfv_idx,
                    coeff_idx,
                    coeff,
                    zkp_modulus
                );
                assert!(
                    coeff <= &u128_max,
                    "message[{}][{}] = {} > u128::MAX = {}",
                    trbfv_idx,
                    coeff_idx,
                    coeff,
                    u128_max
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounds::DecBfvBounds;
    use crate::sample::generate_sample_decryption;
    use shared::circuit::SampleType;
    use shared::utils::test_parameters_bfv;

    #[test]
    fn test_vector_computation() {
        use shared::utils::test_parameters_trbfv;
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();
        let data = generate_sample_decryption(
            &bfv_params,
            &trbfv_params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        // Use the honest_ciphertexts directly (now in correct format: H parties, L TRBFV bases each)
        let honest_cts: &[Vec<Ciphertext>] = &data.honest_ciphertexts;

        // Calculate bit_sk for commitment computation
        let (_, bounds) = DecBfvBounds::compute(&bfv_params, &trbfv_params, 0).unwrap();
        let bit_sk = shared::template::calculate_bit_width(&bounds.s_bound.to_string()).unwrap();

        let vectors = DecBfvVectors::compute(
            &honest_cts,
            &data.secret_key,
            &bfv_params,
            &trbfv_params,
            bit_sk,
            &data.message,
        )
        .unwrap();

        // Verify structure
        assert_eq!(vectors.honest_c0.len(), data.num_honest_parties);
        assert_eq!(vectors.sum_c0.len(), trbfv_params.moduli().len());
        assert_eq!(vectors.sum_c1.len(), trbfv_params.moduli().len());
        assert_eq!(vectors.s.len(), bfv_params.degree());
        assert_eq!(vectors.u_i.len(), trbfv_params.moduli().len());
    }

    #[test]
    fn test_standard_form() {
        let vecs = DecBfvVectors::new(3, 2, 2, 512); // H=3, L=2, L_PRIME=2, N=512
        let std_form = vecs.standard_form();

        // Check that all vectors are properly reduced
        let p = shared::constants::get_zkp_modulus();
        // u_global is now [L][N] - 2D
        for trbfv_u_global in &std_form.u_global {
            assert!(trbfv_u_global.iter().all(|x| x < &p));
        }
        // message is now [L][N] - 2D
        for trbfv_msg in &std_form.message {
            assert!(trbfv_msg.iter().all(|x| x < &p));
        }
    }

    #[test]
    fn test_validation_with_real_data() {
        use shared::utils::test_parameters_trbfv;
        let bfv_params = test_parameters_bfv();
        let trbfv_params = test_parameters_trbfv();
        let data = generate_sample_decryption(
            &bfv_params,
            &trbfv_params,
            SampleType::SecretKey,
            None,
            shared::DEFAULT_INSECURE_LAMBDA,
        )
        .unwrap();

        // Use the honest_ciphertexts directly (now in correct format: H parties, L TRBFV bases each)
        let honest_cts: &[Vec<Ciphertext>] = &data.honest_ciphertexts;

        // Calculate bit_sk for commitment computation
        let (_, bounds) = DecBfvBounds::compute(&bfv_params, &trbfv_params, 0).unwrap();
        let bit_sk = shared::template::calculate_bit_width(&bounds.s_bound.to_string()).unwrap();

        let vectors = DecBfvVectors::compute(
            &honest_cts,
            &data.secret_key,
            &bfv_params,
            &trbfv_params,
            bit_sk,
            &data.message,
        )
        .unwrap();

        // Convert to standard form (this will call validate_for_circuit)
        let std_form = vectors.standard_form();

        // If we get here, validation passed
        let zkp_modulus = shared::constants::get_zkp_modulus();

        // Spot check a few values
        // u_global is now [L][N] - 2D
        for trbfv_u_global in &std_form.u_global {
            assert!(
                trbfv_u_global
                    .iter()
                    .all(|x| x >= &BigInt::zero() && x < &zkp_modulus)
            );
        }
        // message is now [L][N] - 2D
        for trbfv_msg in &std_form.message {
            assert!(
                trbfv_msg
                    .iter()
                    .all(|x| x >= &BigInt::zero() && x < &zkp_modulus)
            );
        }

        // Check that small values are within u128::MAX
        let u128_max = BigInt::from(u128::MAX);
        for trbfv_msg in &std_form.message {
            assert!(trbfv_msg.iter().all(|x| x <= &u128_max));
        }
    }
}
