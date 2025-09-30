use std::sync::Arc;

use fhe::trbfv::ShamirSecretSharing;
use num_bigint::{BigInt, BigUint, RandBigInt, Sign, ToBigInt};
use num_traits::Zero;
use pvw::params::PvwParameters;
use rand::rngs::ThreadRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use serde_json::json;
use shared::{
    get_zkp_modulus,
    utils::{
        reduce_1d, reduce_2d, reduce_3d, to_string_1d_vec, to_string_2d_vec, to_string_3d_vec,
    },
};

/// Full set of witness vectors for sk_shares circuit.
#[derive(Clone, Debug)]
pub struct SkSharesVectors {
    pub sk: Vec<BigInt>,                // [N] constant-first (flat)
    pub f: Vec<Vec<Vec<BigInt>>>,       // [N][L][t] constant-first with c0 = a_i
    pub y: Vec<Vec<Vec<BigInt>>>,       // [N][L][P] residues
    pub r: Vec<Vec<Vec<BigInt>>>,       // [N][L][P] quotients
    pub d: Vec<Vec<BigInt>>,            // [N][L] (will be 0)
    pub f_randomness: Vec<Vec<BigInt>>, // [N][L]
    pub x_coords: Vec<BigInt>,          // [P]
}

impl SkSharesVectors {
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

    pub fn compute(
        params: &Arc<PvwParameters>,
        mut rng: ThreadRng,
    ) -> Result<SkSharesVectors, Box<dyn std::error::Error>> {
        let t = params.t;
        let n_parties = params.n;
        let degree = params.l;
        let moduli = params.moduli();
        let l = moduli.len();

        let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

        let sk_bn: Vec<BigUint> = Vec::from(&params.sample_secret_polynomial(&mut rng)?);
        println!("{:#?}", sk_bn);
        let mut sk: Vec<BigInt> = sk_bn.iter().map(|x| x.to_bigint().unwrap()).collect();
        assert!(
            sk.len() >= degree,
            "PVW secret returned fewer than N coefficients"
        );
        sk.truncate(degree);

        let mut f = vec![vec![vec![BigInt::zero(); t]; l]; degree];
        let mut y = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
        let mut r = vec![vec![vec![BigInt::zero(); n_parties]; l]; degree];
        let mut d = vec![vec![BigInt::zero(); l]; degree];
        let mut f_randomness = vec![vec![BigInt::zero(); l]; degree];

        for i in 0..degree {
            let a_i = &sk[i];
            for (j, &qj_u) in moduli.iter().enumerate() {
                let qj = BigInt::from(qj_u);

                // Shamir poly over Z_qj, degree t-1, with exact c0 = a_i
                let sss = ShamirSecretSharing::new(t - 1, n_parties, qj.clone());
                f[i][j] = sample_f_polynomial(&sss, a_i); // c0 = a_i

                let c0 = f[i][j][0].clone();

                // a_i - c0 = d_{i,j} * q_j
                let (d_ij, rem) = div_rem_euclid(&(a_i - &c0), &qj);
                debug_assert!(rem.is_zero());
                d[i][j] = d_ij;

                // shares: f(x_k) = r*q_j + y, with 0 ≤ y < q_j
                for (k_idx, xk) in x_coords.iter().enumerate() {
                    let mut acc = BigInt::zero();
                    for coeff in f[i][j].iter().rev() {
                        acc = xk * &acc + coeff;
                    }
                    let (rk, yk) = div_rem_euclid(&acc, &qj);
                    r[i][j][k_idx] = rk;
                    y[i][j][k_idx] = yk;
                }

                // commitment randomness in symmetric range
                let bj = BigInt::from((qj_u - 1) / 2);
                let rand_ij = rng.gen_bigint_range(&-bj.clone(), &(&bj + 1)); // upper bound exclusive
                f_randomness[i][j] = rand_ij;
            }
        }

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

    /// Convert to JSON format for serialization (arrays of strings, no wrappers)
    pub fn to_json(&self) -> serde_json::Value {
        json!({
            "sk": to_string_1d_vec(&self.sk),                    // [N]
            "f": to_string_3d_vec(&self.f),                      // [N][L][T]
            "y": to_string_3d_vec(&self.y),                      // [N][L][P]
            "r": to_string_3d_vec(&self.r),                      // [N][L][P]
            "d": to_string_2d_vec(&self.d),                      // [N][L]
            "f_randomness": to_string_2d_vec(&self.f_randomness),// [N][L]
            "x_coords": to_string_1d_vec(&self.x_coords),        // [P]
        })
    }
}

fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}

fn sample_f_polynomial(sss: &ShamirSecretSharing, secret: &BigInt) -> Vec<BigInt> {
    // c0 equals the actual secret coefficient a_i (not reduced mod q_j)
    let c0 = secret.clone();

    // other coeffs uniform in [0, q_j) to keep coefficients well-bounded
    let low = BigInt::from(0);
    let high = sss.prime.clone();
    let random_coefficients: Vec<BigInt> = (0..sss.threshold)
        .into_par_iter()
        .map(|_| {
            let mut rng = rand::thread_rng();
            rng.gen_bigint_range(&low, &high)
        })
        .collect();

    let mut coefficients = Vec::with_capacity(1 + sss.threshold);
    coefficients.push(c0);
    coefficients.extend(random_coefficients);
    coefficients
}
