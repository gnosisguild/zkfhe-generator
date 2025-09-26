use crate::sample::PvwEncryptionData;
use bigint_poly::{Polynomial, reduce_and_center_coefficients_mut, reduce_in_ring, reduce_scalar};
use fhe_math::rq::Representation;
use itertools::izip;
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use pvw::PvwParameters;
use rayon::iter::{ParallelBridge, ParallelIterator};
use serde_json::json;
use shared::constants::get_zkp_modulus;
use shared::errors::ZkFheResult;
use shared::utils::{to_string_3d_vec, to_string_4d_vec};
use std::sync::Arc;

/// Matrix type representing a 2D array of polynomials
/// ROWS x COLS matrix where each entry is a polynomial of degree N
pub type Matrix = Vec<Vec<Vec<BigInt>>>;

/// Vector type representing a 1D array of polynomials  
/// SIZE vector where each entry is a polynomial of degree N
pub type Vector = Vec<Vec<BigInt>>;

#[derive(Clone, Debug)]
pub struct PkPvwVectors {
    /// Common Reference String (CRS) matrices
    /// One KxK matrix per modulus l: [Matrix<K, K, N>; L]
    /// Structure: a[l][row][col] where each entry is a polynomial of degree N
    pub a: Vec<Matrix>, // L matrices of K x K polynomials

    /// Party error vectors (secret witness)
    /// Each party i has an error vector e[i] of K polynomials with small coefficients
    /// Structure: Matrix<N_PARTIES, K, N>
    /// e[party][k_dim] where each entry is a polynomial of degree N
    pub e: Matrix, // N_PARTIES x K matrix of polynomials

    /// Party secret keys (secret witness)
    /// Each party i has a secret key sk[i] of K polynomials from CBD distribution
    /// Structure: Matrix<N_PARTIES, K, N>
    /// sk[party][k_dim] where each entry is a polynomial of degree N
    pub sk: Matrix, // N_PARTIES x K matrix of polynomials

    /// Party public keys (public output)
    /// b[l][i] is party i's public key vector for modulus l
    /// Structure: [Matrix<N_PARTIES, K, N>; L]
    /// b[l][party][k_dim] where each entry is a polynomial of degree N
    pub b: Vec<Matrix>, // L matrices of N_PARTIES x K polynomials

    /// Quotients from modulus switching (secret witness)
    /// r1[l][i] are quotients from modulus switching for party i, modulus l (can be negative)
    /// Structure: [Matrix<N_PARTIES, K, 2*N-1>; L]
    /// r1[l][party][k_dim] where each entry is a polynomial of degree 2*N-1
    pub r1: Vec<Matrix>, // L matrices of N_PARTIES x K polynomials (degree 2*N-1)

    /// Quotients from cyclotomic reduction (secret witness)
    /// r2[l][i] are quotients from cyclotomic reduction for party i, modulus l (typically positive)
    /// Structure: [Matrix<N_PARTIES, K, 2*N-1>; L]
    /// r2[l][party][k_dim] where each entry is a polynomial of degree 2*N-1
    pub r2: Vec<Matrix>, // L matrices of N_PARTIES x K polynomials (degree 2*N-1)
}

impl PkPvwVectors {
    /// Create a new PkPvwVectors with the given parameters
    ///
    /// # Arguments
    /// * `n_parties` - Number of parties (N_PARTIES)
    /// * `k` - LWE dimension (K)
    /// * `n` - Ring dimension/polynomial degree (N)
    /// * `num_moduli` - Number of moduli (L in the circuit)
    pub fn new(n_parties: usize, k: usize, n: usize, num_moduli: usize) -> Self {
        PkPvwVectors {
            // a: L matrices of K x K polynomials of degree N
            a: vec![vec![vec![vec![BigInt::zero(); n]; k]; k]; num_moduli],
            // e: N_PARTIES x K matrix of polynomials of degree N
            e: vec![vec![vec![BigInt::zero(); n]; k]; n_parties],
            // sk: N_PARTIES x K matrix of polynomials of degree N
            sk: vec![vec![vec![BigInt::zero(); n]; k]; n_parties],
            // b: L matrices of N_PARTIES x K polynomials of degree N
            b: vec![vec![vec![vec![BigInt::zero(); n]; k]; n_parties]; num_moduli],
            // r1: L matrices of N_PARTIES x K polynomials of degree 2*N-1
            r1: vec![vec![vec![vec![BigInt::zero(); 2 * n - 1]; k]; n_parties]; num_moduli],
            // r2: L matrices of N_PARTIES x K polynomials of degree 2*N-1
            r2: vec![vec![vec![vec![BigInt::zero(); 2 * n - 1]; k]; n_parties]; num_moduli],
        }
    }

    /// Create PkPvwVectors from sample PVW encryption data
    /// Following the complete Greco pattern for all vectors computation
    pub fn compute(
        encryption_data: &PvwEncryptionData,
        params: &Arc<PvwParameters>,
    ) -> ZkFheResult<Self> {
        let n_parties = params.n; // Number of parties
        let k = params.k; // LWE dimension  
        let n = params.l; // Ring dimension/polynomial degree (from PVW l parameter)
        let num_moduli = params.context.moduli().len(); // Number of moduli (L in the circuit)

        // Create the vectors structure
        let mut vectors = Self::new(n_parties, k, n, num_moduli);
        let parties = &encryption_data.parties;
        let _global_pk = &encryption_data.global_pk;
        let _crs = &encryption_data.crs;

        // Create cyclotomic polynomial x^N + 1
        let mut cyclo = vec![BigInt::from(0u64); (n + 1) as usize];
        cyclo[0] = BigInt::from(1u64); // x^N term
        cyclo[n as usize] = BigInt::from(1u64); // x^0 term

        // ================== QI-INDEPENDENT COMPUTATIONS ==================

        // Extract secret keys (sk) - N_PARTIES×K matrix of polynomials (qi-independent)
        for (party_idx, party) in parties.iter().enumerate() {
            for k_idx in 0..k {
                let sk_coeffs = party.secret_key.get_coefficients(k_idx).unwrap();

                // Convert i64 coefficients to BigInt and reverse (following Greco pattern)
                // Do NOT center/reduce here - PVW secret keys are already in correct distribution
                vectors.sk[party_idx][k_idx] = sk_coeffs
                    .iter()
                    .rev() // Reverse order like in Greco
                    .map(|&coeff| BigInt::from(coeff))
                    .collect();
            }
        }

        // Extract error vectors (e) - N_PARTIES×K matrix of polynomials (qi-independent)
        let all_errors = _global_pk.get_all_errors();
        for (party_idx, _party) in parties.iter().enumerate() {
            for k_idx in 0..k {
                if let Some(party_errors) = all_errors.get(party_idx) {
                    if let Some(error_poly) = party_errors.get(k_idx) {
                        // Extract coefficients using the FHE pattern
                        let mut error_poly_copy = error_poly.clone();
                        error_poly_copy.change_representation(Representation::PowerBasis);

                        // Get coefficients and apply Greco pattern processing
                        let error_coeffs = error_poly_copy.coefficients();
                        if let Some(coeffs_slice) = error_coeffs.row(0).as_slice() {
                            // Convert to centered representation using first modulus operator
                            let error_centered = unsafe {
                                params.context.moduli_operators()[0].center_vec_vt(coeffs_slice)
                            };

                            // Convert to BigInt and reverse (following Greco pattern)
                            vectors.e[party_idx][k_idx] = error_centered
                                .iter()
                                .rev()
                                .map(|&coeff| BigInt::from(coeff))
                                .collect();
                        } else {
                            vectors.e[party_idx][k_idx] = vec![BigInt::zero(); n];
                        }
                    } else {
                        vectors.e[party_idx][k_idx] = vec![BigInt::zero(); n];
                    }
                } else {
                    vectors.e[party_idx][k_idx] = vec![BigInt::zero(); n];
                }
            }
        }

        // ================== QI-DEPENDENT COMPUTATIONS ==================

        // Get moduli operators and values from context
        let moduli_ops = params.context.moduli_operators();
        let qis: Vec<u64> = params.moduli().to_vec();

        // Process each modulus in parallel (following Greco pattern)
        let results: Vec<_> = izip!(moduli_ops.iter(), qis.iter())
            .enumerate()
            .par_bridge()
            .map(|(modulus_idx, (qi_op, &qi))| {
                let qi_bigint = BigInt::from(qi);

                // Initialize results for this modulus
                let mut a_l = vec![vec![vec![BigInt::zero(); n]; k]; k]; // K x K matrix
                let mut b_l = vec![vec![vec![BigInt::zero(); n]; k]; n_parties]; // N_PARTIES x K matrix
                let mut r1_l = vec![vec![vec![BigInt::zero(); 2 * n - 1]; k]; n_parties]; // N_PARTIES x K matrix
                let mut r2_l = vec![vec![vec![BigInt::zero(); n - 1]; k]; n_parties]; // N_PARTIES x K matrix

                // Extract CRS matrix a_l - K×K matrix for this modulus
                for row in 0..k {
                    for col in 0..k {
                        // Extract CRS coefficients using the FHE pattern
                        if let Some(crs_poly) = _crs.get(row, col) {
                            // 1. Clone and change to PowerBasis representation
                            let mut crs_poly_copy = crs_poly.clone();
                            crs_poly_copy.change_representation(Representation::PowerBasis);

                            // 2. Extract modulus component for this qi
                            let crs_coeffs = crs_poly_copy.coefficients();
                            if let Some(coeffs_slice) = crs_coeffs.row(modulus_idx).as_slice() {
                                // 3. Convert to BigInt and reverse (following Greco qi-dependent pattern)
                                a_l[row][col] = coeffs_slice
                                    .iter()
                                    .rev()
                                    .map(|&x| BigInt::from(x))
                                    .collect();

                                // 4. Reduce and center modulo qi (like Greco qi-dependent processing)
                                reduce_and_center_coefficients_mut(&mut a_l[row][col], &qi_bigint);
                            } else {
                                a_l[row][col] = vec![BigInt::zero(); n];
                            }
                        } else {
                            a_l[row][col] = vec![BigInt::zero(); n];
                        }
                    }
                }

                // Process each party's public key for this modulus
                for party_idx in 0..n_parties {
                    for k_idx in 0..k {
                        // Extract actual public key b[l][party][k_idx] (i.e., b_l_i_k)
                        let mut b_l_i_k = vec![BigInt::zero(); n];
                        if let Some(pk_poly) = _global_pk.get_polynomial(party_idx, k_idx) {
                            // 1. Clone and change to PowerBasis representation
                            let mut pk_poly_copy = pk_poly.clone();
                            pk_poly_copy.change_representation(Representation::PowerBasis);

                            // 2. Extract modulus component for this qi
                            let pk_coeffs = pk_poly_copy.coefficients();
                            if let Some(coeffs_slice) = pk_coeffs.row(modulus_idx).as_slice() {
                                // 3. Convert to BigInt and reverse (following Greco qi-dependent pattern)
                                b_l_i_k = coeffs_slice
                                    .iter()
                                    .rev()
                                    .map(|&x| BigInt::from(x))
                                    .collect();

                                // 4. Reduce and center modulo qi (like Greco qi-dependent processing)
                                reduce_and_center_coefficients_mut(&mut b_l_i_k, &qi_bigint);
                            }
                        }

                        // ===== Compute theoretical public key b̂ = a*s + e =====
                        // Following circuit's matrix multiplication: a_l * s_i
                        // Circuit does: a_times_s[row] += a_at_gamma[row][col] * sk_at_gamma[i][col];
                        // So we compute: sum over col of a_l[k_idx][col] * s_i[col]

                        let mut b_hat_poly = Polynomial::new(vec![BigInt::zero()]);

                        // Matrix multiplication S*A,: k_idx-th component = sum of s[row] * A[row][k_idx]

                        for row in 0..k {
                            let s_poly = Polynomial::new(vectors.sk[party_idx][row].clone()); // s[row]
                            let a_poly = Polynomial::new(a_l[row][k_idx].clone()); // A[row][k_idx]
                            let product = s_poly.mul(&a_poly); // s[row] * A[row][k_idx]
                            b_hat_poly = b_hat_poly.add(&product);
                        }

                        // Add error vector e[party_idx][k_idx]
                        let e_poly = Polynomial::new(vectors.e[party_idx][k_idx].clone());
                        b_hat_poly = b_hat_poly.add(&e_poly);

                        let b_hat_unreduced = b_hat_poly.coefficients().to_vec();

                        // ===== FOLLOW GRECO PATTERN EXACTLY FOR PVW =====
                        // Step 9: Calculate Difference (b - b̂) - Greco pattern, no expansion needed
                        let b_l_i_k_poly = Polynomial::new(b_l_i_k.clone());
                        let b_hat_poly = Polynomial::new(b_hat_unreduced.clone());
                        let b_l_i_k_minus_b_hat =
                            b_l_i_k_poly.sub(&b_hat_poly).coefficients().to_vec();

                        // Step 10: Reduce and Center the Difference (for r₂)
                        let mut b_l_i_k_minus_b_hat_mod_zqi = b_l_i_k_minus_b_hat.clone();
                        reduce_and_center_coefficients_mut(
                            &mut b_l_i_k_minus_b_hat_mod_zqi,
                            &qi_bigint,
                        );

                        // Step 11: Calculate r₂ following Greco pattern exactly
                        let b_l_i_k_minus_b_hat_poly =
                            Polynomial::new(b_l_i_k_minus_b_hat_mod_zqi.clone());
                        let cyclo_poly = Polynomial::new(cyclo.clone());
                        let (r2_poly, r2_rem_poly) =
                            b_l_i_k_minus_b_hat_poly.div(&cyclo_poly).unwrap();
                        let mut r2_coeffs = r2_poly.coefficients().to_vec();
                        let r2_rem = r2_rem_poly.coefficients().to_vec();
                        assert!(r2_rem.iter().all(|x| x.is_zero()));

                        // Pad r2 to degree 2*N-1 as expected by the circuit
                        while r2_coeffs.len() < (n - 1) {
                            r2_coeffs.push(BigInt::zero());
                        }

                        // Step 12-13: Calculate r₁ following Greco pattern exactly
                        let r2_original_poly = Polynomial::new(r2_poly.coefficients().to_vec());
                        let r2_times_cyclo =
                            r2_original_poly.mul(&cyclo_poly).coefficients().to_vec();
                        let b_l_i_k_minus_b_hat_original_poly =
                            Polynomial::new(b_l_i_k_minus_b_hat.clone());
                        let r2_cyclo_poly = Polynomial::new(r2_times_cyclo.clone());
                        let r1_numerator = b_l_i_k_minus_b_hat_original_poly
                            .sub(&r2_cyclo_poly)
                            .coefficients()
                            .to_vec();

                        // Step 14: Calculate r₁ (Modular Quotient)
                        let r1_num_poly = Polynomial::new(r1_numerator.clone());
                        let qi_poly = Polynomial::new(vec![qi_bigint.clone()]);
                        let (r1_poly, r1_rem_poly) = r1_num_poly.div(&qi_poly).unwrap();
                        let r1_coeffs = r1_poly.coefficients().to_vec();
                        let r1_rem = r1_rem_poly.coefficients().to_vec();
                        assert!(r1_rem.iter().all(|x| x.is_zero()));

                        // ===== VERIFICATION: Following Greco pattern =====
                        // Verify: b_l_i_k = b_hat_unreduced + r1*qi + r2*cyclo (mod ring)
                        let b_hat_unreduced_poly = Polynomial::new(b_hat_unreduced.clone());
                        let r1_times_qi = Polynomial::new(r1_coeffs.clone()).scalar_mul(&qi_bigint);
                        let r2_times_cyclo = Polynomial::new(r2_coeffs.clone()).mul(&cyclo_poly);

                        // The RHS should be: b_hat + r1*qi + r2*cyclo
                        let rhs = b_hat_unreduced_poly.add(&r1_times_qi).add(&r2_times_cyclo);

                        // Reduce RHS to ring to compare with b_l_i_k
                        let mut rhs_coeffs = rhs.coefficients().to_vec();
                        reduce_in_ring(&mut rhs_coeffs, &cyclo, &qi_bigint);

                        // Verification: b_l_i_k == reduced_RHS
                        assert_eq!(
                            b_l_i_k, rhs_coeffs,
                            "PVW equation verification failed for party {}, k_idx {}, modulus {}",
                            party_idx, k_idx, modulus_idx
                        );

                        // Store results
                        b_l[party_idx][k_idx] = b_l_i_k.clone();
                        r1_l[party_idx][k_idx] = r1_coeffs;
                        r2_l[party_idx][k_idx] = r2_coeffs;
                    }
                }

                (modulus_idx, a_l, b_l, r1_l, r2_l)
            })
            .collect();

        // Merge results back into vectors structure
        for (modulus_idx, a_l, b_l, r1_l, r2_l) in results {
            vectors.a[modulus_idx] = a_l;
            vectors.b[modulus_idx] = b_l;
            vectors.r1[modulus_idx] = r1_l;
            vectors.r2[modulus_idx] = r2_l;
        }

        Ok(vectors)
    }

    /// Convert to standard form (reduce modulo ZKP modulus) - Noir compatible (non-negative values)
    pub fn standard_form(&self) -> Self {
        let zkp_modulus = &get_zkp_modulus();

        // Helper function to reduce coefficients using reduce_scalar for Noir compatibility
        let reduce_1d = |vec: &[BigInt]| -> Vec<BigInt> {
            vec.iter().map(|x| reduce_scalar(x, zkp_modulus)).collect()
        };

        let reduce_2d = |vec: &[Vec<BigInt>]| -> Vec<Vec<BigInt>> {
            vec.iter().map(|row| reduce_1d(row)).collect()
        };

        let reduce_3d = |vec: &[Vec<Vec<BigInt>>]| -> Vec<Vec<Vec<BigInt>>> {
            vec.iter().map(|matrix| reduce_2d(matrix)).collect()
        };

        let reduce_4d = |vec: &[Vec<Vec<Vec<BigInt>>>]| -> Vec<Vec<Vec<Vec<BigInt>>>> {
            vec.iter().map(|matrix_3d| reduce_3d(matrix_3d)).collect()
        };

        PkPvwVectors {
            a: reduce_4d(&self.a),
            e: reduce_3d(&self.e),
            sk: reduce_3d(&self.sk),
            b: reduce_4d(&self.b),
            r1: reduce_4d(&self.r1),
            r2: reduce_4d(&self.r2),
        }
    }

    /// Convert to JSON format for serialization
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "a": to_string_4d_vec(&self.a),
            "e": to_string_3d_vec(&self.e),
            "sk": to_string_3d_vec(&self.sk),
            "b": to_string_4d_vec(&self.b),
            "r1": to_string_4d_vec(&self.r1),
            "r2": to_string_4d_vec(&self.r2),
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use pvw::{GlobalPublicKey, Party, PvwCrs, PvwParametersBuilder};
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use std::sync::Arc;

    #[test]
    fn test_with_exact_main_moduli() {
        // Using the exact moduli from your working main.rs run
        // From your output: PVW primes used (4): 0x800000022a0001, 0x800000021a0001, 0x80000002120001, 0x80000001f60001

        let working_moduli = vec![
            0x800000022a0001, // 56 bits
            0x800000021a0001, // 56 bits
            0x80000002120001, // 56 bits
            0x80000001f60001, // 56 bits
        ];

        println!("=== Using exact moduli from working main.rs run ===");
        println!("Moduli: {:?}", working_moduli);

        let params = PvwParametersBuilder::new()
            .set_parties(1)
            .set_l(8) // ell from your output
            .set_dimension(2) // Keep small for debugging
            .set_moduli(&working_moduli)
            .set_error_bound_1(BigInt::from(100u64)) // Much smaller than your 98207502014
            .set_error_bound_2(BigInt::from(100u64)) // Much smaller than your 18014398509481984
            .build_arc()
            .expect("These moduli should work since they worked in main.rs");

        println!("✅ PVW parameters created with exact main.rs moduli");

        let mut rng = StdRng::seed_from_u64(12345);
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to generate CRS");
        println!("✅ CRS generated");

        let mut parties = Vec::new();
        let party = Party::new(0, &params, &mut rng).expect("Failed to create party");
        parties.push(party);
        println!("✅ Party created");

        let mut global_pk = GlobalPublicKey::new(crs.clone());
        global_pk
            .generate_and_add_party_with_errors(&parties[0], &mut rng)
            .expect("Failed to generate party key");
        println!("✅ Global public key generated");

        let sample_data = PvwEncryptionData {
            parties,
            global_pk,
            crs,
        };

        println!("=== Calling PkPvwVectors::compute ===");
        let result = PkPvwVectors::compute(&sample_data, &params);

        match result {
            Ok(_) => println!("✅ Compute succeeded with exact main.rs moduli!"),
            Err(e) => {
                println!("❌ Compute failed even with working moduli: {:?}", e);
                panic!("Compute should work with proven moduli");
            }
        }
    }

    #[test]
    fn test_pvw_compute_debug() {
        // Use smaller parameters for easier debugging
        let working_moduli = vec![
            0x800000022a0001, // 56 bits
            0x800000021a0001, // 56 bits
            0x80000002120001, // 56 bits
            0x80000001f60001, // 56 bits
        ];

        let params = PvwParametersBuilder::new()
            .set_parties(1)
            .set_l(8) // Ring dimension N = 8
            .set_dimension(2) // k = 2 for easier debugging
            .set_moduli(&working_moduli)
            .set_error_bound_1(BigInt::from(100u64))
            .set_error_bound_2(BigInt::from(100u64))
            .build_arc()
            .expect("Failed to build PVW parameters");

        let mut rng = StdRng::seed_from_u64(12345);
        let crs = PvwCrs::new(&params, &mut rng).expect("Failed to generate CRS");

        let mut parties = Vec::new();
        let party = Party::new(0, &params, &mut rng).expect("Failed to create party");
        parties.push(party);

        let mut global_pk = GlobalPublicKey::new(crs.clone());
        global_pk
            .generate_and_add_party_with_errors(&parties[0], &mut rng)
            .expect("Failed to generate party key");

        let sample_data = PvwEncryptionData {
            parties,
            global_pk,
            crs,
        };

        // This should trigger the assertion failure
        let result = PkPvwVectors::compute(&sample_data, &params);

        match result {
            Ok(_) => println!("Unexpectedly succeeded - the bug might be fixed!"),
            Err(e) => {
                println!("Expected error occurred: {:?}", e);
                // The panic should happen in the parallel execution
            }
        }
    }

    #[test]
    fn test_cyclotomic_division_simple() {
        // Test cyclotomic polynomial division with simple examples
        let n = 8;

        // Create cyclotomic polynomial x^8 + 1
        let mut cyclo = vec![BigInt::zero(); n + 1];
        cyclo[0] = BigInt::from(1u64); // x^8 coefficient (highest degree first)
        cyclo[n] = BigInt::from(1u64); // constant term

        println!("Cyclotomic polynomial coefficients: {:?}", cyclo);

        // Test case 1: Simple polynomial that should divide evenly
        // Let's try x^8 (should give quotient = 1, remainder = -1)
        let mut test_poly = vec![BigInt::zero(); n + 1];
        test_poly[0] = BigInt::from(1u64); // x^8 coefficient (highest degree first)

        let dividend = Polynomial::new(test_poly);
        let divisor = Polynomial::new(cyclo.clone());

        println!("Testing division of x^8 by (x^8 + 1)");
        match dividend.div(&divisor) {
            Ok((quotient, remainder)) => {
                println!("Quotient coeffs: {:?}", quotient.coefficients());
                println!("Remainder coeffs: {:?}", remainder.coefficients());
                println!("Is remainder zero? {}", remainder.is_zero());
            }
            Err(e) => println!("Division failed: {:?}", e),
        }

        // Test case 2: Random polynomial from your failing case
        // Use one of the failing differences from your output
        let failing_diff = vec![
            BigInt::from(-8237159346722366i64),
            BigInt::from(-11714862123042894i64),
            BigInt::from(3751421192042854i64),
            BigInt::from(-12619095310568690i64),
            BigInt::from(-12013833035694017i64),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
        ];

        let failing_poly = Polynomial::new(failing_diff);

        println!("\nTesting division of failing polynomial by (x^8 + 1)");
        match failing_poly.div(&divisor) {
            Ok((quotient, remainder)) => {
                println!("Quotient coeffs: {:?}", quotient.coefficients());
                println!("Remainder coeffs: {:?}", remainder.coefficients());
                println!("Is remainder zero? {}", remainder.is_zero());
                println!(
                    "Remainder non-zero elements: {:?}",
                    remainder
                        .coefficients()
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| !c.is_zero())
                        .collect::<Vec<_>>()
                );
            }
            Err(e) => println!("Division failed: {:?}", e),
        }
    }

    #[test]
    fn test_polynomial_arithmetic_debug() {
        // Debug the specific polynomial operations causing issues
        let n = 8;

        // Simulate the problematic case from your debug output
        let b_l_i_k = vec![
            BigInt::from(10858459017053810i64),
            BigInt::from(-5998813417927846i64),
            BigInt::from(-4593204969235642i64),
            BigInt::from(960653490501250i64),
            BigInt::from(4418435061656363i64),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
        ];

        let b_hat_unreduced = vec![
            BigInt::from(8237159346722366i64),
            BigInt::from(11714862123042894i64),
            BigInt::from(-3751421192042854i64),
            BigInt::from(-23409701743653647i64),
            BigInt::from(-24014964018528320i64),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
            BigInt::zero(),
        ];

        println!(
            "Original lengths: b_l_i_k={}, b_hat_unreduced={}",
            b_l_i_k.len(),
            b_hat_unreduced.len()
        );

        // Step 1: Reduce b_hat_unreduced by cyclotomic polynomial first
        let mut cyclo = vec![BigInt::zero(); n + 1];
        cyclo[0] = BigInt::from(1u64); // x^8 coefficient (highest degree first)
        cyclo[n] = BigInt::from(1u64); // constant term

        let b_hat_unreduced_poly = Polynomial::new(b_hat_unreduced);
        let cyclo_poly = Polynomial::new(cyclo.clone());

        match b_hat_unreduced_poly.div(&cyclo_poly) {
            Ok((quotient, remainder)) => {
                println!("b_hat reduction successful:");
                println!("  Quotient: {:?}", quotient.coefficients());
                println!("  Remainder: {:?}", remainder.coefficients());

                // Now compute difference with same-degree polynomials
                let b_l_i_k_poly = Polynomial::new(b_l_i_k);
                let diff = b_l_i_k_poly.sub(&remainder);

                println!("Difference after reduction: {:?}", diff.coefficients());

                // Test if this difference divides evenly by cyclotomic
                match diff.div(&cyclo_poly) {
                    Ok((q, r)) => {
                        println!("Final division successful:");
                        println!("  Quotient r2: {:?}", q.coefficients());
                        println!("  Remainder: {:?}", r.coefficients());
                        println!("  Is remainder zero? {}", r.is_zero());
                    }
                    Err(e) => println!("Final division failed: {:?}", e),
                }
            }
            Err(e) => println!("b_hat reduction failed: {:?}", e),
        }
    }

    #[test]
    fn test_simple_cyclotomic_division() {
        // Test with n=2: x^2 + 1
        let cyclo = vec![
            BigInt::from(1), // x^2 coefficient
            BigInt::from(0), // x^1 coefficient
            BigInt::from(1), // x^0 coefficient (constant term)
        ];
        let cyclo_poly = Polynomial::new(cyclo);

        // Test 1: Divide x^2 by (x^2 + 1) - should give quotient=1, remainder=-1
        let x2 = vec![
            BigInt::from(1), // x^2
            BigInt::from(0), // x^1
            BigInt::from(0), // x^0
        ];
        let x2_poly = Polynomial::new(x2);

        println!("Dividing x^2 by (x^2 + 1):");
        println!("Dividend: {:?}", x2_poly.coefficients());
        println!("Divisor:  {:?}", cyclo_poly.coefficients());

        match x2_poly.div(&cyclo_poly) {
            Ok((q, r)) => {
                println!("Quotient: {:?}", q.coefficients());
                println!("Remainder: {:?}", r.coefficients());
                println!("Is remainder zero? {}", r.is_zero());

                // Verify: x^2 = (x^2 + 1) * quotient + remainder
                let verification = cyclo_poly.mul(&q).add(&r);
                println!(
                    "Verification (should equal x^2): {:?}",
                    verification.coefficients()
                );
                println!("Original x^2: {:?}", x2_poly.coefficients());
            }
            Err(e) => println!("Division error: {:?}", e),
        }
    }
}
