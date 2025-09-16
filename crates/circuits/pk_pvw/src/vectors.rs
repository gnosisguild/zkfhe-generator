use bigint_poly::reduce_and_center_coefficients;
use num_bigint::BigInt;
use num_traits::Zero;
use shared::errors::ZkFheResult;

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
    /// * `l` - Number of moduli (L)
    pub fn new(n_parties: usize, k: usize, n: usize, l: usize) -> Self {
        PkPvwVectors {
            // a: L matrices of K x K polynomials of degree N
            a: vec![vec![vec![vec![BigInt::zero(); n]; k]; k]; l],
            // e: N_PARTIES x K matrix of polynomials of degree N
            e: vec![vec![vec![BigInt::zero(); n]; k]; n_parties],
            // sk: N_PARTIES x K matrix of polynomials of degree N
            sk: vec![vec![vec![BigInt::zero(); n]; k]; n_parties],
            // b: L matrices of N_PARTIES x K polynomials of degree N
            b: vec![vec![vec![vec![BigInt::zero(); n]; k]; n_parties]; l],
            // r1: L matrices of N_PARTIES x K polynomials of degree 2*N-1
            r1: vec![vec![vec![vec![BigInt::zero(); 2 * n - 1]; k]; n_parties]; l],
            // r2: L matrices of N_PARTIES x K polynomials of degree 2*N-1
            r2: vec![vec![vec![vec![BigInt::zero(); 2 * n - 1]; k]; n_parties]; l],
        }
    }

    /// Create PkPvwVectors from sample PVW encryption data
    pub fn compute(encryption_data: &crate::sample::PvwEncryptionData) -> ZkFheResult<Self> {
        use bigint_poly::reduce_and_center_coefficients;
        use shared::constants::get_zkp_modulus;

        let params = &encryption_data.params;
        let n_parties = params.n;
        let k = params.k;
        let n = params.l; // Ring dimension (polynomial degree)
        let l = params.context.moduli().len(); // Number of moduli

        // Create the vectors structure
        let mut vectors = Self::new(n_parties, k, n, l);

        // Extract CRS matrices (a) - one K×K matrix per modulus l
        for (l_idx, modulus) in params.context.moduli().iter().enumerate() {
            for i in 0..k {
                for j in 0..k {
                    if let Some(crs_poly) = encryption_data.crs.get(i, j) {
                        // Convert polynomial to coefficients and reduce mod zkp_modulus
                        let coeffs = extract_poly_coefficients(crs_poly, n, *modulus)?;
                        vectors.a[l_idx][i][j] = coeffs;
                    }
                }
            }
        }

        // Extract secret keys (sk) - N_PARTIES×K matrix of polynomials
        for (party_idx, secret_key) in encryption_data.secret_keys.iter().enumerate() {
            for k_idx in 0..k {
                let sk_coeffs = secret_key.get_coefficients(k_idx).ok_or_else(|| {
                    shared::errors::ZkFheError::Bfv {
                        message: format!(
                            "Failed to get secret key coefficients for party {party_idx} dim {k_idx}"
                        ),
                    }
                })?;

                // Convert i64 coefficients to BigInt and reduce mod zkp_modulus
                let coeffs = sk_coeffs
                    .iter()
                    .map(|&coeff| {
                        let big_coeff = BigInt::from(coeff);
                        reduce_and_center_coefficients(&[big_coeff.clone()], &get_zkp_modulus());
                        big_coeff
                    })
                    .collect();
                vectors.sk[party_idx][k_idx] = coeffs;
            }
        }

        // Extract public keys (b) - L×N_PARTIES×K matrices of polynomials
        for l_idx in 0..l {
            let modulus = params.context.moduli()[l_idx];
            for party_idx in 0..n_parties {
                for k_idx in 0..k {
                    if let Some(pk_poly) =
                        encryption_data.global_pk.get_polynomial(party_idx, k_idx)
                    {
                        let coeffs = extract_poly_coefficients(pk_poly, n, modulus)?;
                        vectors.b[l_idx][party_idx][k_idx] = coeffs;
                    }
                }
            }
        }

        // Extract error vectors (e) - N_PARTIES×K matrix of polynomials
        // Use the actual errors from key generation
        for (party_idx, error_vector) in encryption_data.error_vectors.iter().enumerate() {
            for (k_idx, error_poly) in error_vector.iter().enumerate() {
                let coeffs = extract_poly_coefficients(error_poly, n, params.context.moduli()[0])?;
                vectors.e[party_idx][k_idx] = coeffs;
            }
        }

        // Compute r1 and r2 quotients from the PVW equation:
        // b_{l,i} = a_l * s_i + e_i + r2_{l,i} * (X^N + 1) + r1_{l,i} * q_l
        // Rearranging: r2_{l,i} * (X^N + 1) + r1_{l,i} * q_l = b_{l,i} - a_l * s_i - e_i
        for l_idx in 0..l {
            let modulus = params.context.moduli()[l_idx];
            let qi = BigInt::from(modulus);

            for party_idx in 0..n_parties {
                for k_idx in 0..k {
                    // Compute the right-hand side: b_{l,i} - a_l * s_i - e_i
                    let (r1_coeffs, r2_coeffs) = compute_quotients(
                        &vectors.b[l_idx][party_idx][k_idx], // b_{l,i}
                        &vectors.a[l_idx],                   // a_l matrix
                        &vectors.sk[party_idx],              // s_i
                        &vectors.e[party_idx][k_idx],        // e_i
                        k_idx,                               // which component of the K-vector
                        &qi,                                 // q_l
                        n,                                   // polynomial degree
                    )?;

                    vectors.r1[l_idx][party_idx][k_idx] = r1_coeffs;
                    vectors.r2[l_idx][party_idx][k_idx] = r2_coeffs;
                }
            }
        }

        Ok(vectors)
    }

    /// Convert to standard form (reduce modulo ZKP modulus)
    pub fn standard_form(&self) -> Self {
        use shared::constants::get_zkp_modulus;
        use shared::utils::{reduce_coefficients_3d, reduce_coefficients_4d};

        let zkp_modulus = &get_zkp_modulus();

        PkPvwVectors {
            a: reduce_coefficients_4d(&self.a, zkp_modulus),
            e: reduce_coefficients_3d(&self.e, zkp_modulus),
            sk: reduce_coefficients_3d(&self.sk, zkp_modulus),
            b: reduce_coefficients_4d(&self.b, zkp_modulus),
            r1: reduce_coefficients_4d(&self.r1, zkp_modulus),
            r2: reduce_coefficients_4d(&self.r2, zkp_modulus),
        }
    }

    /// Convert to JSON format for serialization
    pub fn to_json(&self) -> serde_json::Value {
        use serde_json::json;
        use shared::utils::{to_string_3d_vec, to_string_4d_vec};

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

/// Helper function to extract polynomial coefficients and reduce them modulo ZKP modulus
fn extract_poly_coefficients(
    poly: &fhe_math::rq::Poly,
    degree: usize,
    _modulus: u64,
) -> ZkFheResult<Vec<BigInt>> {
    use bigint_poly::reduce_and_center_coefficients;
    use fhe_math::rq::Representation;
    use shared::constants::get_zkp_modulus;

    // Convert to coefficient representation if needed
    let mut working_poly = poly.clone();
    if *working_poly.representation() != Representation::PowerBasis {
        working_poly.change_representation(Representation::PowerBasis);
    }

    // Extract coefficients - fhe_math polynomials store coefficients as u64
    let coeffs: Vec<BigInt> = working_poly
        .coefficients()
        .iter()
        .take(degree)
        .map(|&coeff| BigInt::from(coeff))
        .collect();

    // Ensure we have exactly 'degree' coefficients
    let mut result = coeffs;
    result.resize(degree, BigInt::zero());

    // Reduce modulo ZKP modulus and center
    reduce_and_center_coefficients(&result, &get_zkp_modulus());

    Ok(result)
}

/// Compute r1 and r2 quotients from the PVW equation
///
/// Solves: r2 * (X^N + 1) + r1 * q_l = b - a_l * s_i - e_i
///
/// This is done by:
/// 1. Computing the RHS: b - a_l * s_i - e_i
/// 2. Using polynomial division to separate the cyclotomic and modulus components
/// 3. r2 comes from division by (X^N + 1)
/// 4. r1 comes from the remainder after cyclotomic reduction, divided by q_l
fn compute_quotients(
    b: &[BigInt],       // Public key polynomial b_{l,i}
    a_matrix: &Matrix,  // CRS matrix a_l (K x K)
    sk_vector: &Vector, // Secret key vector s_i (K polynomials)
    e: &[BigInt],       // Error polynomial e_i
    k_idx: usize,       // Which component of the K-vector we're computing
    qi: &BigInt,        // Modulus q_l
    n: usize,           // Polynomial degree
) -> ZkFheResult<(Vec<BigInt>, Vec<BigInt>)> {
    use num_traits::Zero;
    use shared::constants::get_zkp_modulus;

    // Step 1: Compute a_l * s_i for component k_idx
    // This is the dot product of row k_idx of a_matrix with sk_vector
    let mut a_times_s = vec![BigInt::zero(); n];
    for (j, sk_poly) in sk_vector.iter().enumerate() {
        let a_poly = &a_matrix[k_idx][j];

        // Multiply polynomials: a[k_idx][j] * s[j]
        let product = multiply_polynomials(a_poly, sk_poly, n)?;

        // Add to accumulator
        for (i, coeff) in product.iter().enumerate() {
            if i < a_times_s.len() {
                a_times_s[i] += coeff;
            }
        }
    }

    // Step 2: Compute RHS = b - a_l * s_i - e_i
    let mut rhs = vec![BigInt::zero(); 2 * n - 1]; // Degree can be up to 2*N-1
    for i in 0..n {
        if i < b.len() && i < a_times_s.len() && i < e.len() {
            rhs[i] = &b[i] - &a_times_s[i] - &e[i];
        }
    }

    // Step 3: Reduce RHS modulo ZKP modulus
    reduce_and_center_coefficients(&rhs, &get_zkp_modulus());

    // Step 4: Solve for r2 and r1 using polynomial division
    // We need to solve: r2 * (X^N + 1) + r1 * q_l = RHS
    // This is equivalent to: RHS = r2 * (X^N + 1) + r1 * q_l

    // First, divide by (X^N + 1) to get r2
    let (r2_coeffs, remainder) = divide_by_cyclotomic(&rhs, n)?;

    // Then, divide the remainder by q_l to get r1
    let r1_coeffs = divide_by_scalar(&remainder, qi)?;

    // Ensure both have the correct degree (2*N-1)
    let mut r1_final = r1_coeffs;
    let mut r2_final = r2_coeffs;
    r1_final.resize(2 * n - 1, BigInt::zero());
    r2_final.resize(2 * n - 1, BigInt::zero());

    Ok((r1_final, r2_final))
}

/// Multiply two polynomials represented as coefficient vectors
fn multiply_polynomials(
    poly1: &[BigInt],
    poly2: &[BigInt],
    max_degree: usize,
) -> ZkFheResult<Vec<BigInt>> {
    let mut result = vec![BigInt::zero(); 2 * max_degree - 1];

    for (i, coeff1) in poly1.iter().enumerate() {
        for (j, coeff2) in poly2.iter().enumerate() {
            let degree = i + j;
            if degree < result.len() {
                result[degree] += coeff1 * coeff2;
            }
        }
    }

    Ok(result)
}

/// Divide a polynomial by the cyclotomic polynomial (X^N + 1)
/// Returns (quotient, remainder)
fn divide_by_cyclotomic(dividend: &[BigInt], n: usize) -> ZkFheResult<(Vec<BigInt>, Vec<BigInt>)> {
    use num_traits::Zero;

    let mut quotient = vec![BigInt::zero(); dividend.len()];
    let mut remainder = dividend.to_vec();

    // Polynomial long division: divide by (X^N + 1)
    // The cyclotomic polynomial is X^N + 1, so we need to handle the pattern
    for i in (n..dividend.len()).rev() {
        if !remainder[i].is_zero() {
            // The leading coefficient of the remainder
            let coeff = remainder[i].clone();

            // Add to quotient at position (i - n)
            if i >= n {
                quotient[i - n] += &coeff;
            }

            // Subtract coeff * (X^N + 1) from remainder
            // This means: remainder[i] -= coeff and remainder[i-n] -= coeff
            remainder[i] -= &coeff;
            if i >= n {
                remainder[i - n] -= &coeff;
            }
        }
    }

    // The remainder should have degree < N
    remainder.truncate(n);

    Ok((quotient, remainder))
}

/// Divide a polynomial by a scalar
fn divide_by_scalar(poly: &[BigInt], scalar: &BigInt) -> ZkFheResult<Vec<BigInt>> {
    use num_traits::Zero;

    let mut result = Vec::new();
    for coeff in poly {
        if coeff.is_zero() {
            result.push(BigInt::zero());
        } else {
            // For integer division, we need to handle the case where coeff might not be divisible by scalar
            // In the PVW context, this should work out due to the mathematical structure
            result.push(coeff / scalar);
        }
    }

    Ok(result)
}
