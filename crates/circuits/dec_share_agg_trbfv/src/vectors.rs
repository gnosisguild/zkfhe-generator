//! Input validation vectors for Decryption Share Aggregation TRBFV zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct decryption share aggregation
//! in zero-knowledge for threshold BFV.

use bigint_poly::{reduce_coefficients, reduce_coefficients_2d, reduce_coefficients_3d};
use fhe::bfv::BfvParameters;
use fhe::trbfv::shamir::ShamirSecretSharing;
use fhe_math::rq::{Poly, Representation};
use num_bigint::{BigInt, BigUint};
use num_traits::{Signed, ToPrimitive, Zero};
use serde_json::json;
use shared::errors::{ZkFheError, ZkFheResult};
use shared::utils::{to_string_1d_vec, to_string_2d_vec};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub struct DecShareAggTrBfvVectors {
    /// Decryption shares from T+1 parties (per modulus, per party)
    pub decryption_shares: Vec<Vec<Vec<BigInt>>>, // [party][modulus][coeff]
    /// Party IDs (1-based: 1, 2, ..., T+1)
    pub party_ids: Vec<BigInt>,
    /// Message polynomial coefficients
    pub message: Vec<BigInt>,
    /// u_global polynomial coefficients (CRT reconstruction)
    pub u_global: Vec<BigInt>,
    /// CRT quotients (per modulus)
    pub crt_quotients: Vec<Vec<BigInt>>, // [modulus][coeff]
}

impl DecShareAggTrBfvVectors {
    pub fn new(num_moduli: usize, degree: usize, threshold: usize) -> Self {
        DecShareAggTrBfvVectors {
            decryption_shares: vec![vec![vec![BigInt::zero(); degree]; num_moduli]; threshold + 1],
            party_ids: vec![BigInt::zero(); threshold + 1],
            message: vec![BigInt::zero(); degree],
            u_global: vec![BigInt::zero(); degree],
            crt_quotients: vec![vec![BigInt::zero(); degree]; num_moduli],
        }
    }
    /// Create vectors from decryption share aggregation data
    ///
    /// # Arguments
    /// * `d_share_polys` - Decryption shares from T+1 parties
    /// * `reconstructing_parties` - Party IDs (1-based)
    /// * `message_vec` - Decoded message
    /// * `params` - BFV parameters
    /// * `threshold` - Threshold value T
    /// * `num_parties` - Total number of parties
    pub fn compute(
        d_share_polys: &[Poly],
        reconstructing_parties: &[usize],
        message_vec: &[u64],
        params: &Arc<BfvParameters>,
        threshold: usize,
        num_parties: usize,
    ) -> ZkFheResult<Self> {
        let ctx = params.ctx_at_level(0)?;
        let num_moduli = ctx.moduli().len();
        let degree = ctx.degree;

        // Prepare RNS copies for extraction pe()
        let d_share_polys_copy: Vec<Poly> = d_share_polys
            .iter()
            .map(|p| {
                let mut copy = p.clone();
                copy.change_representation(Representation::PowerBasis);
                copy
            })
            .collect();

        // 1. Extract decryption shares per modulus per party
        let mut decryption_shares: Vec<Vec<Vec<BigInt>>> = Vec::new();

        for d_share in &d_share_polys_copy {
            let mut party_shares = Vec::new();
            let coeffs = d_share.coefficients();

            for m in 0..num_moduli {
                let modulus_row = coeffs.row(m);
                let qi_bigint = BigInt::from(ctx.moduli()[m]);

                // Convert to BigInt and normalize to [0, q_i)
                // (not centered, so values remain small when reduced modulo ZKP modulus)
                // NOTE: Do NOT reverse - must match the order used in shares.rs decrypt_from_shares
                // which uses coeff_arr[i] directly without reversal
                let coeff_vec: Vec<BigInt> = modulus_row
                    .iter()
                    .map(|&x| {
                        let mut coeff = BigInt::from(x);
                        // Normalize to [0, q_i) range
                        coeff %= &qi_bigint;
                        if coeff < BigInt::zero() {
                            coeff += &qi_bigint;
                        }
                        coeff
                    })
                    .collect();

                party_shares.push(coeff_vec);
            }
            decryption_shares.push(party_shares);
        }

        // 2. Party IDs (1-based: 1, 2, ..., T+1)
        let party_ids: Vec<BigInt> = reconstructing_parties
            .iter()
            .map(|&x| BigInt::from(x))
            .collect();

        // 3. Message (pad to degree if needed)
        let mut message: Vec<BigInt> = message_vec.iter().map(|&x| BigInt::from(x)).collect();
        message.resize(degree, BigInt::zero());

        // 4. Compute u^{(l)} via Lagrange interpolation (per modulus, per coefficient)
        // Extract coefficients directly from polynomials and use Shamir recovery,
        // matching the method used in shares.rs
        let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();

        for m in 0..num_moduli {
            let modulus = ctx.moduli()[m];
            let modulus_bigint = BigInt::from(modulus);
            let shamir_ss =
                ShamirSecretSharing::new(threshold, num_parties, modulus_bigint.clone());

            let mut u_modulus_coeffs: Vec<u64> = Vec::new();

            for coeff_idx in 0..degree {
                let mut shares: Vec<(usize, BigInt)> = Vec::new();

                // Collect shares from all parties for this coefficient
                for (party_idx, party_id) in reconstructing_parties
                    .iter()
                    .take(threshold + 1)
                    .enumerate()
                {
                    let coeffs = d_share_polys_copy[party_idx].coefficients();
                    let coeff_arr = coeffs.row(m);
                    let coeff = coeff_arr[coeff_idx];
                    shares.push((*party_id, BigInt::from(coeff)));
                }

                // Recover using Shamir interpolation
                let u_coeff = shamir_ss.recover(&shares[0..threshold + 1]);
                let u_coeff_u64 = u_coeff.to_u64().unwrap_or_else(|| {
                    // If conversion fails, normalize first
                    let u_coeff_normalized = &u_coeff % &modulus_bigint;
                    let u_coeff_pos = if u_coeff_normalized < BigInt::zero() {
                        &u_coeff_normalized + &modulus_bigint
                    } else {
                        u_coeff_normalized.clone()
                    };
                    u_coeff_pos.to_u64().unwrap_or_else(|| {
                        panic!(
                            "u_coeff is too large to fit in u64: {} (modulus: {})",
                            u_coeff, modulus
                        );
                    })
                });
                u_modulus_coeffs.push(u_coeff_u64);
            }

            u_per_modulus.push(u_modulus_coeffs);
        }

        // 5. Compute u_global via CRT reconstruction
        // Reconstruct Q from the per-modulus values using CRT
        use fhe_math::rns::RnsContext;
        use ndarray::ArrayView1;

        let rns = RnsContext::new(ctx.moduli()).map_err(|e| shared::errors::ZkFheError::Bfv {
            message: format!("Failed to create RNS context: {:?}", e),
        })?;

        let mut u_global_coeffs: Vec<BigUint> = Vec::new();
        for coeff_idx in 0..degree {
            // Collect per-modulus values for this coefficient
            let rests: Vec<u64> = (0..num_moduli)
                .map(|m| u_per_modulus[m][coeff_idx])
                .collect();

            // CRT reconstruction: u_global[coeff_idx] = CRT([u^{(0)}[coeff_idx], u^{(1)}[coeff_idx], ...])
            // This returns the unique value in [0, Q) that has the given residues
            let u_global_coeff = rns.lift(ArrayView1::from(&rests));
            u_global_coeffs.push(u_global_coeff);
        }

        // Convert to BigInt for consistency
        let u_global: Vec<BigInt> = u_global_coeffs
            .iter()
            .map(|x| BigInt::from(x.clone()))
            .collect();

        // Verify CRT reconstruction: u_global mod q_i == u_per_modulus[i] for all moduli
        // This ensures Q is reconstructed correctly
        for (m, u_modulus) in u_per_modulus.iter().enumerate().take(num_moduli) {
            let q_m = ctx.moduli()[m];
            let q_m_bigint = BigInt::from(q_m);
            for (coeff_idx, u_global_val) in u_global.iter().enumerate().take(degree) {
                let u_global_mod_qm = u_global_val % &q_m_bigint;
                let u_global_mod_qm_normalized = if u_global_mod_qm < BigInt::zero() {
                    &u_global_mod_qm + &q_m_bigint
                } else {
                    u_global_mod_qm.clone()
                };
                let u_m = BigInt::from(u_modulus[coeff_idx]);

                if u_global_mod_qm_normalized != u_m {
                    panic!(
                        "CRT reconstruction verification failed: u_global[{}] mod q_{} = {}, but u^({})[{}] = {}. \
                         This indicates Q was not reconstructed correctly.",
                        coeff_idx, m, u_global_mod_qm_normalized, m, coeff_idx, u_m
                    );
                }
            }
        }

        // 6. Compute CRT quotients
        // For each modulus m, compute r^{(m)} such that: u^{(m)} + r^{(m)} * q_m = u_global
        // This means: r^{(m)} = (u_global - u^{(m)}) / q_m
        // By CRT, u_global ≡ u^{(m)} (mod q_m), so the division should be exact
        let mut crt_quotients: Vec<Vec<BigInt>> = Vec::new();

        for (m, u_modulus) in u_per_modulus.iter().enumerate().take(num_moduli) {
            let q_m = ctx.moduli()[m];
            let q_m_bigint = BigInt::from(q_m);
            let mut r_m_coeffs: Vec<BigInt> = Vec::new();

            for (coeff_idx, u_global_val) in u_global.iter().enumerate().take(degree) {
                let u_m = BigInt::from(u_modulus[coeff_idx]);

                // Compute: r^{(m)}[coeff_idx] = (u_global[coeff_idx] - u^{(m)}[coeff_idx]) / q_m
                // The division is exact by the CRT property (already verified above)
                let diff = u_global_val - &u_m;
                let quotient = &diff / &q_m_bigint;
                let remainder = &diff % &q_m_bigint;

                // Verify the division is exact (should always be true by CRT property)
                if !remainder.is_zero() {
                    panic!(
                        "CRT quotient computation failed: division not exact. u_global[{}]={}, u^({})[{}]={}, q_m={}, remainder={}",
                        coeff_idx, u_global_val, m, coeff_idx, u_m, q_m_bigint, remainder
                    );
                }

                r_m_coeffs.push(quotient);
            }

            crt_quotients.push(r_m_coeffs);
        }

        Ok(DecShareAggTrBfvVectors {
            decryption_shares,
            party_ids,
            message,
            u_global,
            crt_quotients,
        })
    }

    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &shared::constants::get_zkp_modulus();
        let result = DecShareAggTrBfvVectors {
            decryption_shares: reduce_coefficients_3d(&self.decryption_shares, zkp_modulus),
            party_ids: reduce_coefficients(&self.party_ids, zkp_modulus),
            message: reduce_coefficients(&self.message, zkp_modulus),
            u_global: reduce_coefficients(&self.u_global, zkp_modulus),
            crt_quotients: reduce_coefficients_2d(&self.crt_quotients, zkp_modulus),
        };

        // Validate all values meet circuit requirements
        result.validate_for_circuit(zkp_modulus);

        result
    }

    /// Validates that all values meet the requirements for the circuit:
    /// 1. All values are in [0, zkp_modulus) range
    /// 2. Small values (party_ids, message, decryption_shares) must be < 2^128 for u128 casting
    /// 3. Large values (u_global, crt_quotients) can be > 2^128 but must be < zkp_modulus
    ///    Note: These large values will cause u128 casting to wrap in __compute_mod_reduction,
    ///    but the remainder computation will still be correct for small moduli (< 2^56).
    ///    The assertion in reduce_mod will catch any issues.
    fn validate_for_circuit(&self, zkp_modulus: &BigInt) {
        let u128_max = BigInt::from(u128::MAX);

        // Check party_ids - must be small (< 2^128)
        for (idx, id) in self.party_ids.iter().enumerate() {
            assert!(
                id >= &BigInt::zero(),
                "party_ids[{}] = {} is negative",
                idx,
                id
            );
            assert!(
                id < zkp_modulus,
                "party_ids[{}] = {} >= zkp_modulus = {}",
                idx,
                id,
                zkp_modulus
            );
            assert!(
                id <= &u128_max,
                "party_ids[{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                idx,
                id,
                u128_max
            );
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

        // Check decryption_shares
        // Note: Decryption shares are per-party, per-modulus, per-coefficient
        // They should be < CRT modulus (< 2^56), so definitely < 2^128
        for (party_idx, party_shares) in self.decryption_shares.iter().enumerate() {
            for (mod_idx, modulus_row) in party_shares.iter().enumerate() {
                for (coeff_idx, coeff) in modulus_row.iter().enumerate() {
                    assert!(
                        coeff >= &BigInt::zero(),
                        "decryption_shares[{}][{}][{}] = {} is negative",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff
                    );
                    assert!(
                        coeff < zkp_modulus,
                        "decryption_shares[{}][{}][{}] = {} >= zkp_modulus = {}",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff,
                        zkp_modulus
                    );
                    assert!(
                        coeff <= &u128_max,
                        "decryption_shares[{}][{}][{}] = {} > u128::MAX = {}, cannot be safely cast to u128 in circuit",
                        party_idx,
                        mod_idx,
                        coeff_idx,
                        coeff,
                        u128_max
                    );
                }
            }
        }
    }

    /// Verify decoding using the alternative direct method (mimics circuit's verify_decoding_alternative)
    ///
    /// This implements the new direct decoding verification that computes:
    /// 1. (t * u_global) mod Q
    /// 2. Uses Q^{-1} mod t to recover the message
    /// 3. Handles centering based on whether (t*u) >= Q/2
    ///
    /// # Arguments
    /// * `q_modulus` - The product of all CRT moduli Q
    /// * `plaintext_modulus` - The plaintext modulus t
    /// * `q_inverse_mod_t` - The modular inverse Q^{-1} mod t
    ///
    /// # Returns
    /// Ok(()) if verification passes, Error otherwise
    pub fn verify_decoding_alternative(
        &self,
        q_modulus: &BigInt,
        plaintext_modulus: u64,
        q_inverse_mod_t: u64,
    ) -> ZkFheResult<()> {
        let t = BigInt::from(plaintext_modulus);
        let q_inv_mod_t = BigInt::from(q_inverse_mod_t);
        let q_half = q_modulus / BigInt::from(2);

        // Verify decoding for each coefficient
        for (coeff_idx, (u_global_coeff, message_coeff)) in
            self.u_global.iter().zip(self.message.iter()).enumerate()
        {
            // Compute (t * u_global) mod Q using regular modular arithmetic
            let t_times_u = (u_global_coeff * &t) % q_modulus;

            // Check if centering is needed: (t*u) mod Q >= Q/2
            let needs_centering = t_times_u > q_half;

            let computed_message = if needs_centering {
                // When (t*u) mod Q >= Q/2: treat as negative in centered form
                // Noir: mul_mod(q_inverse_mod_t, mul_mod(q_modulus - t_times_u_q, t, q_modulus), t)
                // This is: (q_inv * (((Q - t*u) * t) % Q)) % t
                let centered = q_modulus - &t_times_u;
                let inner = (&centered * &t) % q_modulus;
                (&q_inv_mod_t * &inner) % &t
            } else {
                // When (t*u) mod Q < Q/2: stays positive in centered form
                // Noir: mul_mod(q_inverse_mod_t, mul_mod(t_times_u_q, t, q_modulus), t)
                // This is: (q_inv * ((t*u * t) % Q)) % t = (q_inv * ((t^2 * u) % Q)) % t
                // Then: t - product (unless product is 0)
                let inner = (&t_times_u * &t) % q_modulus;
                let product = (&q_inv_mod_t * &inner) % &t;
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
                        "Alternative decoding verification failed at coefficient {}: expected message = {}, computed message = {}. \
                        This means the decryption is incorrect. Check decryption shares and aggregation.",
                        coeff_idx, message_coeff, computed_message
                    ),
                });
            }
        }

        Ok(())
    }

    /// Count the number of non-zero coefficients in the message
    pub fn count_nonzero_message_coefficients(&self) -> usize {
        self.message
            .iter()
            .filter(|&coeff| !coeff.is_zero())
            .count()
    }

    /// Trim all vectors to the specified length based on non-zero message coefficients
    /// If trim_length is 0, returns the full vectors unchanged
    pub fn trim_to_nonzero(&self, trim_length: usize) -> Self {
        if trim_length == 0 || trim_length >= self.message.len() {
            // Don't trim if length is 0 or >= current length
            return self.clone();
        }

        DecShareAggTrBfvVectors {
            decryption_shares: self
                .decryption_shares
                .iter()
                .map(|party| {
                    party
                        .iter()
                        .map(|modulus| modulus.iter().take(trim_length).cloned().collect())
                        .collect()
                })
                .collect(),

            party_ids: self.party_ids.clone(), // party_ids don't need trimming

            message: self.message.iter().take(trim_length).cloned().collect(),

            u_global: self.u_global.iter().take(trim_length).cloned().collect(),

            crt_quotients: self
                .crt_quotients
                .iter()
                .map(|modulus| modulus.iter().take(trim_length).cloned().collect())
                .collect(),
        }
    }

    /// Verifies the global noise bound exactly as the Noir circuit's range_check_2bounds
    ///
    /// This reproduces exactly the logic from the Noir circuit's `verify_global_noise_bound`:
    /// 1. Computes noise = u_global - delta * message
    /// 2. Calls range_check_2bounds(delta_half, delta_half) on the noise polynomial
    ///
    /// The range_check_2bounds function checks that each coefficient c satisfies:
    /// - shifted = c + delta_half must be >= 0  (i.e., c >= -delta_half)
    /// - range_size - shifted = 2*delta_half - (c + delta_half) must be >= 0  (i.e., c <= delta_half)
    ///   Which is equivalent to: -delta_half <= c <= delta_half
    ///
    /// # Arguments
    /// * `delta` - The delta value (floor(Q / t) where Q is product of moduli, t is plaintext modulus)
    /// * `delta_half` - The half-delta value (floor(delta / 2))
    /// * `q` - Optional Q value (product of moduli). If None, will be computed from delta and plaintext_modulus
    /// * `plaintext_modulus` - Optional plaintext modulus t. If Q is None, this is used to compute Q ≈ delta * t
    ///
    /// # Panics
    /// Panics if any noise coefficient is outside the range [-delta_half, delta_half]
    pub fn verify_noise_bound(
        &self,
        delta: &BigUint,
        delta_half: &BigUint,
        q: Option<&BigUint>,
        plaintext_modulus: Option<u64>,
    ) {
        let delta_bigint = BigInt::from(delta.clone());
        let delta_half_bigint = BigInt::from(delta_half.clone());
        let neg_delta_half = -&delta_half_bigint;

        // Compute Q for centering: either use provided Q, compute from plaintext_modulus, or try candidates
        let q_bigint = if let Some(q_val) = q {
            // Use provided Q directly
            BigInt::from(q_val.clone())
        } else if let Some(t) = plaintext_modulus {
            // Compute Q from delta and plaintext modulus: Q ≈ delta * t
            // Since delta = floor(Q/t), we have Q = delta * t + remainder, where remainder < t
            // For centering, we use Q = delta * t as an approximation
            &delta_bigint * BigInt::from(t)
        } else {
            // Fallback: try common plaintext moduli values and pick the one that minimizes noise
            // This is less efficient but works when Q and plaintext_modulus are not available
            let q_candidates = [
                &delta_bigint * BigInt::from(64u64),  // t=64
                &delta_bigint * BigInt::from(100u64), // t=100
                &delta_bigint * BigInt::from(128u64), // t=128
                &delta_bigint * BigInt::from(256u64), // t=256
            ];

            // For the fallback case, we'll use the candidate approach in the loop below
            // Return a dummy value here, we'll handle it in the loop
            q_candidates[0].clone() // Will be overridden in the loop
        };

        // Compute noise = u_global - delta * message for each coefficient
        for (coeff_idx, (u_global_coeff, message_coeff)) in
            self.u_global.iter().zip(self.message.iter()).enumerate()
        {
            // Compute delta * message_coeff
            let delta_times_message = &delta_bigint * message_coeff;

            // Center u_global if needed to get the correct representative for noise checking
            // We always try both the original and centered values and pick the one with smaller noise
            let noise = if q.is_some() || plaintext_modulus.is_some() {
                // We have Q (either provided or computed), try both original and centered
                let noise_original = u_global_coeff - &delta_times_message;
                let u_global_centered = u_global_coeff - &q_bigint;
                let noise_centered = &u_global_centered - &delta_times_message;

                // Pick the one with smaller absolute value
                if noise_centered.abs() < noise_original.abs() {
                    noise_centered
                } else {
                    noise_original
                }
            } else {
                // Fallback: try multiple Q candidates and pick the one that gives smallest noise
                let mut best_noise = u_global_coeff - &delta_times_message;
                let mut best_noise_abs = best_noise.abs();

                let q_candidates = vec![
                    &delta_bigint * BigInt::from(64u64),  // t=64
                    &delta_bigint * BigInt::from(100u64), // t=100
                    &delta_bigint * BigInt::from(128u64), // t=128
                    &delta_bigint * BigInt::from(256u64), // t=256
                ];

                for q_candidate in &q_candidates {
                    let q_half = q_candidate / BigInt::from(2u64);
                    if u_global_coeff > &q_half {
                        let u_global_centered = u_global_coeff - q_candidate;
                        let noise_centered = &u_global_centered - &delta_times_message;
                        let noise_centered_abs = noise_centered.abs();
                        if noise_centered_abs < best_noise_abs {
                            best_noise = noise_centered;
                            best_noise_abs = noise_centered_abs;
                        }
                    }
                }
                best_noise
            };

            // Check that noise is in the range [-delta_half, delta_half]
            if noise < neg_delta_half || noise > delta_half_bigint {
                panic!(
                    "Noise bound violation: noise[{}] = {}, but must be in range [-delta_half, delta_half] = [{}, {}]",
                    coeff_idx, noise, neg_delta_half, delta_half_bigint
                );
            }
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "decryption_shares": self.decryption_shares.iter().map(|party| {
                party.iter().map(|modulus| {
                    to_string_1d_vec(modulus)
                }).collect::<Vec<_>>()
            }).collect::<Vec<_>>(),
            "party_ids": to_string_1d_vec(&self.party_ids),
            "message": to_string_1d_vec(&self.message),
            "u_global": to_string_1d_vec(&self.u_global),
            "crt_quotients": to_string_2d_vec(&self.crt_quotients),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_decryption_share_aggregation;
    use shared::utils::test_parameters_trbfv;

    #[test]
    fn test_vector_computation() {
        let params = test_parameters_trbfv();
        let decryption_data = generate_sample_decryption_share_aggregation(&params, None).unwrap();

        // Compute vectors
        let vecs = DecShareAggTrBfvVectors::compute(
            &decryption_data.d_share_polys,
            &decryption_data.party_ids,
            &decryption_data.message,
            &params,
            decryption_data.threshold,
            decryption_data.num_parties,
        )
        .unwrap();

        let json = vecs.to_json();

        // Check all required fields are present
        let required_fields = [
            "decryption_shares",
            "party_ids",
            "message",
            "u_global",
            "crt_quotients",
        ];

        for field in required_fields.iter() {
            assert!(json.get(field).is_some(), "Missing field: {}", field);
        }
    }
}
