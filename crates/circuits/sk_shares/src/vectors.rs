//! Witness generation for the `sk_shares` circuit.
//!
//! This module produces the full set of vectors required by the circuit:
//! - the secret key coefficients `sk`,
//! - per‐coefficient/per‐modulus Shamir polynomials `f[i][j]`,
//! - residue shares `y[i][j][k]` and quotient shares `r[i][j][k]` s.t.
//!   `f_{i,j}(x_k) = r_{i,j,k} * q_j + y_{i,j,k}` with `0 ≤ y < q_j`,
//! - lift gaps `d[i][j] = (a_i - f_{i,j}(0)) / q_j`,
//! - commitment randomness `f_randomness[i][j]`,
//! - and public evaluation points `x_coords[k] = k`.
//!
//! Coefficient order:
//! - Internally, Shamir polynomials are built in **constant-first** order
//!   `[c0, c1, …, c_T]` with `c0 = a_i`.
//! - Before returning, each `f[i][j]` is **reversed** to highest-first order
//!   to match circuit evaluation semantics.

use fhe::trbfv::ShamirSecretSharing;
use fhe_util::sample_vec_cbd_f32;
use num_bigint::{BigInt, RandBigInt, Sign};
use num_traits::Zero;
use rand::rngs::ThreadRng;
use shared::{
    get_zkp_modulus,
    utils::{reduce_1d, reduce_2d, reduce_3d},
};

/// Container for all witness vectors consumed by the `sk_shares` circuit.
///
/// Shapes:
/// - `sk`: `[N]`
/// - `f`: `[N][L][T+1]` (returned highest-first)
/// - `y`: `[N][L][P]`
/// - `r`: `[N][L][P]`
/// - `d`: `[N][L]`
/// - `f_randomness`: `[N][L]`
/// - `x_coords`: `[P]`
#[derive(Clone, Debug)]
pub struct SkSharesVectors {
    pub sk: Vec<BigInt>,
    pub f: Vec<Vec<Vec<BigInt>>>,
    pub y: Vec<Vec<Vec<BigInt>>>,
    pub r: Vec<Vec<Vec<BigInt>>>,
    pub d: Vec<Vec<BigInt>>,
    pub f_randomness: Vec<Vec<BigInt>>,
    pub x_coords: Vec<BigInt>,
}

impl SkSharesVectors {
    /// Allocates zero-initialized buffers with the requested dimensions.
    ///
    /// - `n_parties` → P
    /// - `n` → N
    /// - `num_moduli` → L
    /// - `t` → degree (allocates `t` coefficients per polynomial)
    pub fn new(n_parties: usize, n: usize, num_moduli: usize, t: usize) -> Self {
        SkSharesVectors {
            sk: vec![BigInt::zero(); n],
            f: vec![vec![vec![BigInt::zero(); t]; num_moduli]; n],
            y: vec![vec![vec![BigInt::zero(); n_parties]; num_moduli]; n],
            r: vec![vec![vec![BigInt::zero(); n_parties]; num_moduli]; n],
            d: vec![vec![BigInt::zero(); num_moduli]; n],
            f_randomness: vec![vec![BigInt::zero(); num_moduli]; n],
            x_coords: vec![BigInt::zero(); n_parties],
        }
    }

    /// Generates all witness vectors.
    ///
    /// Inputs:
    /// - `degree` (`N`): number of secret coefficients.
    /// - `moduli` (`[q_j]`, length `L`): CRT moduli.
    /// - `n_parties` (`P`): number of evaluation points (`x_k = 1..=P`).
    /// - `t` (`T`): Shamir polynomial degree (each polynomial has `T+1` coefficients).
    /// - `rng`: randomness source.
    ///
    /// Process:
    /// 1. Builds `x_coords = [1,2,…,P]`.
    /// 2. Samples `sk` via centered binomial (CBD) with small variance.
    /// 3. For each `(i,j)`, samples a degree-`t` Shamir polynomial over `Z_{q_j}`
    ///    with constant term `a_i`, then computes `d[i][j]`, and splits
    ///    evaluations at each `x_k` into `(r,y)` by Euclidean division.
    /// 4. Samples symmetric commitment randomness per `(i,j)`.
    /// 5. Reverses each `f[i][j]` to highest-first order for the circuit.
    ///
    /// Returns the populated `SkSharesVectors`.
    ///
    /// Panics if:
    /// - `moduli` is empty,
    /// - `n_parties >= min_j q_j` (evaluation points would collide mod `q_j`).
    pub fn compute(
        degree: usize,
        moduli: &[u64],
        n_parties: usize,
        t: usize,
        mut rng: ThreadRng,
    ) -> Result<SkSharesVectors, Box<dyn std::error::Error>> {
        assert!(degree > 0 && n_parties > 0 && !moduli.is_empty());
        let min_q = *moduli.iter().min().unwrap();
        assert!((n_parties as u64) < min_q, "need n_parties < min(q_j)");

        let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

        let sk_cbd = sample_vec_cbd_f32(degree, 0.5, &mut rng)?;
        let sk: Vec<BigInt> = sk_cbd.into_iter().map(BigInt::from).collect();

        let l = moduli.len();
        let mut f = vec![vec![vec![BigInt::zero(); t + 1]; l]; degree];
        let mut y = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
        let mut r = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
        let mut d = vec![vec![BigInt::zero(); l]; degree];
        let mut f_randomness = vec![vec![BigInt::zero(); l]; degree];

        for i in 0..degree {
            let a_i = &sk[i];
            for (j, &qj_u) in moduli.iter().enumerate() {
                let qj = BigInt::from(qj_u);

                // Degree-t Shamir over Z_qj ⇒ returns t+1 coeffs (c0=a_i plus t randoms)
                let sss = ShamirSecretSharing::new(t, n_parties, qj.clone());
                f[i][j] = sss.sample_polynomial(a_i.clone());

                let c0 = f[i][j][0].clone();
                let (d_ij, rem) = div_rem_euclid(&(a_i - &c0), &qj);
                debug_assert!(rem.is_zero());
                d[i][j] = d_ij;

                // shares: f(x_k) = r*q_j + y, 0 ≤ y < q_j
                for (k_idx, xk) in x_coords.iter().enumerate() {
                    let mut acc = BigInt::zero();
                    for coeff in f[i][j].iter().rev() {
                        acc = xk * &acc + coeff;
                    }
                    let (rk, yk) = div_rem_euclid(&acc, &qj);
                    r[i][j][k_idx] = rk;
                    y[i][j][k_idx] = yk;
                }

                let bj = BigInt::from((qj_u - 1) / 2);
                f_randomness[i][j] = rng.gen_bigint_range(&-bj.clone(), &(&bj + 1));
            }
        }

        // Convert polynomials from constant-first to highest-first for the circuit.
        let f: Vec<Vec<Vec<BigInt>>> = f
            .into_iter()
            .map(|row| {
                row.into_iter()
                    .map(|mut coeffs_const_first| {
                        coeffs_const_first.reverse();
                        coeffs_const_first
                    })
                    .collect()
            })
            .collect();

        Ok(SkSharesVectors {
            sk,
            f,
            y,
            r,
            d,
            f_randomness,
            x_coords,
        })
    }

    /// Reduces all vectors into the circuit’s base field.
    ///
    /// Applies modular reduction with the global ZK modulus to each component and
    /// returns a new `SkSharesVectors` in canonical form for serialization.
    pub fn standard_form(&self) -> Self {
        let p = get_zkp_modulus();

        SkSharesVectors {
            sk: reduce_1d(&self.sk, &p),
            f: reduce_3d(&self.f, &p),
            y: reduce_3d(&self.y, &p),
            r: reduce_3d(&self.r, &p),
            d: reduce_2d(&self.d, &p),
            f_randomness: reduce_2d(&self.f_randomness, &p),
            x_coords: reduce_1d(&self.x_coords, &p),
        }
    }
}

/// Euclidean division with non-negative remainder.
///
/// Returns `(quotient, remainder)` such that:
/// - `a = quotient * n + remainder`
/// - `0 ≤ remainder < |n|`
fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}
