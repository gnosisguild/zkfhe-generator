use fhe::trbfv::ShamirSecretSharing;
use fhe_util::sample_vec_cbd_f32;
use num_bigint::{BigInt, RandBigInt, Sign};
use num_traits::Zero;
use rand::rngs::ThreadRng;
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use shared::{
    get_zkp_modulus,
    utils::{reduce_1d, reduce_2d, reduce_3d},
};

/// Full set of witness vectors for sk_shares circuit.
#[derive(Clone, Debug)]
pub struct SkSharesVectors {
    pub sk: Vec<BigInt>,                // [N] constant-first
    pub f: Vec<Vec<Vec<BigInt>>>,       // [N][L][t+1] constant-first with c0 = a_i
    pub y: Vec<Vec<Vec<BigInt>>>,       // [N][L][P] residues
    pub r: Vec<Vec<Vec<BigInt>>>,       // [N][L][P] quotients
    pub d: Vec<Vec<BigInt>>,            // [N][L]
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
        degree: usize,    // BFV ring N (number of SK coefficients)
        moduli: &[u64],   // BFV RNS moduli
        n_parties: usize, // number of shares (x_k = 1..=n_parties)
        t: usize,
        mut rng: ThreadRng,
    ) -> Result<SkSharesVectors, Box<dyn std::error::Error>> {
        assert!(degree > 0 && n_parties > 0 && !moduli.is_empty());
        let min_q = *moduli.iter().min().unwrap();
        assert!((n_parties as u64) < min_q, "need n_parties < min(q_j)");

        let x_coords: Vec<BigInt> = (1..=n_parties).map(|k| BigInt::from(k as u64)).collect();

        // CBD(1) secret, len = degree
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
                f[i][j] = sample_f_polynomial(&sss, a_i); // len == t+1

                // a_i - c0 = d_{i,j} * q_j  (here d_{i,j} == 0)
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

                // symmetric commitment randomness
                let bj = BigInt::from((qj_u - 1) / 2);
                f_randomness[i][j] = rng.gen_bigint_range(&-bj.clone(), &(&bj + 1));
            }
        }

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

fn div_rem_euclid(a: &BigInt, n: &BigInt) -> (BigInt, BigInt) {
    let mut r = a % n;
    if r.sign() == Sign::Minus {
        r += n;
    }
    let q = (a - &r) / n;
    (q, r)
}

fn sample_f_polynomial(sss: &ShamirSecretSharing, secret: &BigInt) -> Vec<BigInt> {
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
