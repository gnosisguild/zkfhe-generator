//! Input validation vectors for Decryption Share Aggregation TRBFV zero-knowledge proofs.
//!
//! This module contains the core data structure and computation logic for generating
//! input validation vectors required for proving correct decryption share aggregation
//! in zero-knowledge for threshold BFV.

use bigint_poly::*;
use fhe::bfv::BfvParameters;
use fhe::trbfv::shamir::ShamirSecretSharing;
use fhe_math::rns::RnsContext;
use fhe_math::rq::{Poly, Representation};
use ndarray::ArrayView1;
use num_bigint::{BigInt, BigUint};
use num_traits::{ToPrimitive, Zero};
use serde_json::json;
use shared::errors::ZkFheResult;
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
        let degree = ctx.degree as usize;

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

                // Convert to BigInt, reverse order, and normalize to [0, q_i)
                // (not centered, so values remain small when reduced modulo ZKP modulus)
                let coeff_vec: Vec<BigInt> = modulus_row
                    .iter()
                    .rev()
                    .map(|&x| {
                        let mut coeff = BigInt::from(x);
                        // Normalize to [0, q_i) range
                        coeff = coeff % &qi_bigint;
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
        // IMPORTANT: Use the normalized decryption_shares (same as what we pass to the circuit)
        // This ensures u_global matches what the circuit computes
        let mut u_per_modulus: Vec<Vec<u64>> = Vec::new();

        for m in 0..num_moduli {
            let modulus = ctx.moduli()[m];
            let shamir_ss = ShamirSecretSharing::new(threshold, num_parties, BigInt::from(modulus));

            let mut u_modulus_coeffs: Vec<u64> = Vec::new();

            // For each coefficient position, perform Lagrange interpolation
            for coeff_idx in 0..degree {
                let mut shares: Vec<(usize, BigInt)> = Vec::new();

                // Collect shares from all parties for this coefficient
                // Use normalized decryption_shares (same values passed to circuit)
                for (party_idx, party_id) in reconstructing_parties
                    .iter()
                    .take(threshold + 1)
                    .enumerate()
                {
                    let coeff = &decryption_shares[party_idx][m][coeff_idx];
                    shares.push((*party_id, coeff.clone()));
                }

                // Recover using Shamir interpolation
                let u_coeff = shamir_ss.recover(&shares[0..threshold + 1]);
                u_modulus_coeffs.push(u_coeff.to_u64().unwrap());
            }

            u_per_modulus.push(u_modulus_coeffs);
        }

        // 5. Compute u_global via CRT reconstruction
        // The rns.lift() function reconstructs the unique value in [0, Q) where Q is the product
        // of all moduli. This value satisfies u_global ≡ u^{(m)} (mod q_m) for all moduli m.
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

        // 6. Compute CRT quotients
        // For each modulus m, compute r^{(m)} such that: u^{(m)} + r^{(m)} * q_m = u_global
        // This means: r^{(m)} = (u_global - u^{(m)}) / q_m
        // By CRT, u_global ≡ u^{(m)} (mod q_m), so the division should be exact
        // Since u_global is in [0, Q) and u^{(m)} is in [0, q_m), we have u_global >= u^{(m)} mod q_m
        // which means u_global = k * q_m + u^{(m)} for some k >= 0, so r^{(m)} = k
        let mut crt_quotients: Vec<Vec<BigInt>> = Vec::new();

        for m in 0..num_moduli {
            let q_m = ctx.moduli()[m];
            let q_m_biguint = BigUint::from(q_m);
            let q_m_bigint = BigInt::from(q_m_biguint.clone());
            let mut r_m_coeffs: Vec<BigInt> = Vec::new();

            for coeff_idx in 0..degree {
                // u^{(m)} is in [0, q_m) from the Shamir interpolation
                let u_m = BigInt::from(u_per_modulus[m][coeff_idx]);
                let u_global_val = &u_global[coeff_idx];

                // Verify CRT property: u_global ≡ u^{(m)} (mod q_m)
                // This should always be true if CRT reconstruction is correct
                let u_global_mod_qm = u_global_val % &q_m_bigint;
                let u_global_mod_qm_normalized = if u_global_mod_qm < BigInt::zero() {
                    &u_global_mod_qm + &q_m_bigint
                } else {
                    u_global_mod_qm.clone()
                };

                // u_m is already in [0, q_m), so no normalization needed
                if u_global_mod_qm_normalized != u_m {
                    panic!(
                        "CRT property violated: u_global[{}] mod q_{} = {}, but u^({})[{}] = {}",
                        coeff_idx, m, u_global_mod_qm_normalized, m, coeff_idx, u_m
                    );
                }

                // Compute: r^{(m)}[coeff_idx] = (u_global[coeff_idx] - u^{(m)}[coeff_idx]) / q_m
                // Since u_global ≡ u_m (mod q_m) and both are non-negative with u_global >= u_m (mod q_m),
                // we have u_global = k * q_m + u_m for some k >= 0, so k = (u_global - u_m) / q_m
                // The division should be exact by the CRT property
                let diff = u_global_val - &u_m;

                // Compute quotient and remainder using Euclidean division
                let quotient = &diff / &q_m_bigint;
                let remainder = &diff % &q_m_bigint;

                // Verify the division is exact (remainder should be 0)
                // This must hold by the CRT property: u_global ≡ u_m (mod q_m) implies exact divisibility
                if !remainder.is_zero() {
                    panic!(
                        "CRT quotient computation failed: division not exact. u_global[{}]={}, u^({})[{}]={}, q_m={}, diff={}, remainder={}",
                        coeff_idx, u_global_val, m, coeff_idx, u_m, q_m_bigint, diff, remainder
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
        for (idx, &ref id) in self.party_ids.iter().enumerate() {
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
        for (idx, &ref coeff) in self.message.iter().enumerate() {
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
        for (idx, &ref coeff) in self.u_global.iter().enumerate() {
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
            for (coeff_idx, &ref coeff) in modulus_row.iter().enumerate() {
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
                for (coeff_idx, &ref coeff) in modulus_row.iter().enumerate() {
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

fn reduce_coefficients_3d(coeffs: &[Vec<Vec<BigInt>>], modulus: &BigInt) -> Vec<Vec<Vec<BigInt>>> {
    coeffs
        .iter()
        .map(|party| reduce_coefficients_2d(party, modulus))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::generate_sample_decryption_share_aggregation;
    use fhe::bfv::BfvParametersBuilder;
    use num_bigint::BigUint;

    #[test]
    fn test_vector_computation() {
        let params = BfvParametersBuilder::new()
            .set_degree(8192)
            .set_plaintext_modulus(16384)
            .set_moduli(&[0x1ffffffea0001, 0x1ffffffe88001, 0x1ffffffe48001])
            .set_variance(10)
            .set_error1_variance(BigUint::from(10u32))
            .build_arc()
            .unwrap();

        let decryption_data = generate_sample_decryption_share_aggregation(&params).unwrap();

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
