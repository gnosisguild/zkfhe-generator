use crate::packing::flatten;
use crate::utils::compute_safe;
use ark_bn254::Fr as Field;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use num_bigint::BigInt;
use num_traits::Zero;

const DS_PK_BFV: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x42, 0x46, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_PK_TRBFV: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x54, 0x52, 0x42, 0x46, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_SECRET: [u8; 64] = [
    0x53, 0x45, 0x43, 0x52, 0x45, 0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_SPM: [u8; 64] = [
    0x53, 0x50, 0x4d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_AGG_SHARES: [u8; 64] = [
    0x41, 0x47, 0x47, 0x5f, 0x53, 0x48, 0x41, 0x52, 0x45, 0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_PK_AGG: [u8; 64] = [
    0x50, 0x4b, 0x5f, 0x41, 0x47, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
#[allow(dead_code)]
const DS_AGGREGATION: [u8; 64] = [
    0x41, 0x47, 0x47, 0x72, 0x65, 0x67, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
#[allow(dead_code)]
const DS_CLG_PK_TRBFV: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x50, 0x4b, 0x5f, 0x54, 0x52, 0x42, 0x46, 0x56, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
#[allow(dead_code)]
const DS_CLG_ENC_BFV: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x45, 0x4e, 0x43, 0x5f, 0x42, 0x46, 0x56, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_CLG_GRECO: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const DS_CLG_DEC_SHARE: [u8; 64] = [
    0x43, 0x4c, 0x47, 0x5f, 0x44, 0x65, 0x63, 0x53, 0x68, 0x61, 0x72, 0x65, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn compute_commitments(
    domain_separator: [u8; 64],
    payload: Vec<Field>,
    output_len: u32,
) -> Vec<Field> {
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, output_len];
    compute_safe(domain_separator, payload, io_pattern)
}

/// Prepare the payload for shares party-modulus commitment.
/// This matches the Noir `prepare_shares_party_modulus_commitment_payload` function exactly.
/// Used in C2 (verify shares circuit).
/// Returns N field elements (shares for each coefficient) plus party_idx and mod_idx.
pub fn prepare_shares_party_modulus_commitment_payload(
    y: &[Vec<Vec<BigInt>>],
    party_idx: usize,
    mod_idx: usize,
) -> Vec<Field> {
    let mut inputs = Vec::new();

    // Add shares y[coeff_idx][mod_idx][party_idx + 1] for each coefficient
    for coeff_y in y {
        let share_value = &coeff_y[mod_idx][party_idx + 1];
        inputs.push(crate::utils::bigint_to_field(share_value));
    }

    // Include party_idx and mod_idx in the hash
    inputs.push(Field::from(party_idx as u64));
    inputs.push(Field::from(mod_idx as u64));

    inputs
}

/// Prepare the payload for L polynomials from values commitment.
/// This matches the Noir `prepare_l_polynomial_commitment_payload` function exactly.
/// Used in C1, C2, C4.
/// Flattens values directly without bit packing.
pub fn prepare_l_polynomial_commitment_payload(
    l_polynomials: &[Vec<BigInt>],
    bit: u32,
) -> Vec<Field> {
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, l_polynomials, bit);

    inputs
}

/// Compute a commitment to two polynomial components by flattening them and hashing.
/// This matches the Noir `compute_pk_agg_commitment` function exactly.
/// Can be used for Greco public key commitments.
///
/// # Arguments
/// * `poly0` - First polynomial component array
/// * `poly1` - Second polynomial component array
/// * `bit` - The bit width for coefficient bounds
pub fn compute_poly_commitment(poly0: &[Vec<BigInt>], poly1: &[Vec<BigInt>], bit: u32) -> BigInt {
    // Step 1: Flatten both polynomial components (matches commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, poly0, bit);
    inputs = flatten(inputs, poly1, bit);

    let commitment = compute_commitments(DS_PK_AGG, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the BFV public key polynomials by flattening them and hashing.
/// This matches the Noir `compute_pk_bfv_commitment` function exactly.
/// Used in BFV encryption circuit (enc_bfv).
pub fn compute_pk_bfv_commitment(pk0: &[Vec<BigInt>], pk1: &[Vec<BigInt>], bit_pk: u32) -> BigInt {
    // Step 1: Flatten pk0is and pk1is (matches prepare_pk_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, pk0, bit_pk);
    inputs = flatten(inputs, pk1, bit_pk);

    // Step 2: Hash using SafeSponge (matches compute_pk_bfv_commitment in Noir)
    let commitment = compute_commitments(DS_PK_BFV, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the TRBFV public key polynomials by flattening them and hashing.
/// This matches the Noir `compute_pk_trbfv_commitment` function exactly.
/// Used in TRBFV public key aggregation circuit (pk_agg_trbfv).
pub fn compute_pk_trbfv_commitment(
    pk0: &[Vec<BigInt>],
    pk1: &[Vec<BigInt>],
    bit_pk: u32,
) -> BigInt {
    // Step 1: Flatten pk0is and pk1is (matches prepare_pk_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, pk0, bit_pk);
    inputs = flatten(inputs, pk1, bit_pk);

    // Step 2: Hash using SafeSponge (matches compute_pk_trbfv_commitment in Noir)
    let commitment = compute_commitments(DS_PK_TRBFV, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the secret key polynomial by flattening it and hashing.
/// This matches the Noir `compute_secret_sk_commitment` function exactly.
pub fn compute_sk_commitment(sk: &[BigInt], bit_sk: u32) -> BigInt {
    // Step 1: Flatten sk (matches sk_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[sk.to_vec()], bit_sk);

    // Step 2: Hash using SafeSponge (matches compute_secret_sk_commitment in Noir)
    let commitment = compute_commitments(DS_SECRET, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the secret (secret key).
/// This matches the Noir `compute_secret_commitment` function exactly.
/// Used in C2a.
pub fn compute_secret_sk_commitment(secret: &[BigInt], bit_secret: u32) -> BigInt {
    // Step 1: Flatten secret (matches prepare_single_polynomial_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[secret.to_vec()], bit_secret);

    // Step 2: Hash using SafeSponge (matches compute_secret_sk_commitment in Noir)
    let commitment = compute_commitments(DS_SECRET, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the smudging noise (e_sm).
/// This matches the Noir `compute_secret_commitment` function exactly.
/// Used in C2b.
pub fn compute_secret_e_sm_commitment(secret: &[Vec<BigInt>], bit_secret: u32) -> BigInt {
    // Step 1: Flatten secret (matches prepare_single_polynomial_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, secret, bit_secret);

    // Step 2: Hash using SafeSponge (matches compute_secret_e_sm_commitment in Noir)
    let commitment = compute_commitments(DS_SECRET, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute aggregated commitment for s or e.
/// This matches the Noir `compute_aggregated_shares_commitment` function exactly.
pub fn compute_aggregated_commitment(values: &[Vec<BigInt>]) -> BigInt {
    // Flatten all coefficients from all bases into a single array
    let mut inputs: Vec<Field> = Vec::new();
    #[allow(clippy::needless_range_loop)]
    for basis_idx in 0..values.len() {
        #[allow(clippy::needless_range_loop)]
        for coeff_idx in 0..values[basis_idx].len() {
            let zkp_modulus = crate::constants::get_zkp_modulus();
            let coeff = &values[basis_idx][coeff_idx];
            let coeff_reduced = if coeff < &BigInt::zero() {
                (coeff % &zkp_modulus) + &zkp_modulus
            } else {
                coeff % &zkp_modulus
            };
            let coeff_biguint = coeff_reduced
                .to_biguint()
                .unwrap_or_else(|| (&zkp_modulus + coeff_reduced).to_biguint().unwrap());
            let coeff_bytes = coeff_biguint.to_bytes_le();
            let coeff_field = Field::from_le_bytes_mod_order(&coeff_bytes);
            inputs.push(coeff_field);
        }
    }

    let commitment = compute_commitments(DS_AGG_SHARES, inputs, 1);
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the message polynomial.
/// This matches the Noir `compute_spm_commitment_from_message` function exactly.
pub fn compute_spm_commitment_from_message(message: &[BigInt], bit_msg: u32) -> BigInt {
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[message.to_vec()], bit_msg);

    let commitment = compute_commitments(DS_SPM, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the message polynomial.
/// Deprecated: use `compute_spm_commitment_from_message`.
pub fn compute_message_commitment(message: &[BigInt], bit_msg: u32) -> BigInt {
    compute_spm_commitment_from_message(message, bit_msg)
}

/// Compute a commitment to shares for a specific party and modulus.
/// This matches the Noir `compute_spm_commitment_from_shares` function exactly.
/// Used in C2 (verify shares circuit).
/// Takes a prepared payload from `prepare_shares_party_modulus_commitment_payload`.
pub fn compute_shares_party_modulus_commitment_from_payload(payload: Vec<Field>) -> BigInt {
    let commitment = compute_commitments(DS_SPM, payload, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to a single polynomial (shares party-modulus commitment).
/// This matches the Noir `compute_spm_commitment_from_message` function exactly.
/// Used in C3 (message), C4 (single polynomial).
/// Takes a single polynomial and uses flatten with BIT_MSG for packing.
/// For C2 (verify shares), use `prepare_shares_party_modulus_commitment_payload` + `compute_shares_party_modulus_commitment_from_payload` instead.
pub fn compute_shares_party_modulus_commitment(share: &[BigInt], bit_msg: u32) -> BigInt {
    // Step 1: Flatten share (matches prepare_single_polynomial_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[share.to_vec()], bit_msg);

    let commitment = compute_commitments(DS_SPM, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute the SPM commitment from shares (party + modulus).
/// This matches the Noir `compute_spm_commitment_from_shares` function exactly.
pub fn compute_spm_commitment_from_shares(
    y: &[Vec<Vec<BigInt>>],
    party_idx: usize,
    mod_idx: usize,
) -> BigInt {
    let payload = prepare_shares_party_modulus_commitment_payload(y, party_idx, mod_idx);
    compute_shares_party_modulus_commitment_from_payload(payload)
}

/// Compute PK aggregation commitment.
/// This matches the Noir `compute_pk_agg_commitment` function exactly.
pub fn compute_pk_agg_commitment(pk0: &[Vec<BigInt>], pk1: &[Vec<BigInt>], bit_pk: u32) -> BigInt {
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, pk0, bit_pk);
    inputs = flatten(inputs, pk1, bit_pk);

    let commitment = compute_commitments(DS_PK_AGG, inputs, 1);

    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute Greco PK aggregation commitment.
/// Deprecated: use `compute_pk_agg_commitment`.
pub fn compute_greco_pk_agg_commitment(payload: Vec<Field>) -> BigInt {
    let commitment = compute_commitments(DS_PK_AGG, payload, 1);
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute Greco challenge commitment.
/// This matches the Noir `compute_greco_challenge_commitment` function exactly.
/// Used in Greco circuit.
/// Verifies pk_commitment using pk0/pk1, then generates challenges from gammas_payload.
pub fn compute_greco_challenge_commitment(
    pk0is: &[Vec<BigInt>],
    pk1is: &[Vec<BigInt>],
    gammas_payload: Vec<Field>,
    pk_commitment: &BigInt,
    bit_pk: u32,
    l: usize,
) -> Vec<BigInt> {
    // Verify pk_commitment matches computed commitment
    let computed_pk_commitment = compute_pk_agg_commitment(pk0is, pk1is, bit_pk);
    if computed_pk_commitment != *pk_commitment {
        panic!(
            "PK commitment mismatch in Greco circuit: expected {}, got {}",
            pk_commitment, computed_pk_commitment
        );
    }

    let challenges = compute_commitments(DS_CLG_GRECO, gammas_payload, 2 * l as u32);

    // Convert Fields to BigInts
    challenges
        .into_iter()
        .map(|challenge_field| {
            let challenge_bytes = challenge_field.into_bigint().to_bytes_le();
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &challenge_bytes)
        })
        .collect()
}

/// Compute aggregated shares commitment from payload.
/// This matches the Noir `compute_aggregated_shares_commitment` function exactly.
/// Used in C6 (dec_share_trbfv circuit).
/// Takes a prepared payload (Vec<Field>) directly.
pub fn compute_aggregated_shares_commitment_from_payload(payload: Vec<Field>) -> BigInt {
    let commitment = compute_commitments(DS_AGG_SHARES, payload, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute aggregated shares commitment (either sk_shares or e_sm_shares).
/// This matches the Noir `compute_aggregated_shares_commitment` function exactly.
/// Used in C4.
/// Takes L polynomials and uses flatten with BIT_MSG for packing.
pub fn compute_aggregated_shares_commitment(aggregated: &[Vec<BigInt>], bit_msg: u32) -> BigInt {
    // Step 1: Flatten aggregated shares (matches prepare_aggregated_shares_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, aggregated, bit_msg);

    // Step 2: Hash using SafeSponge (matches compute_aggregated_shares_commitment in Noir)
    let commitment = compute_commitments(DS_AGG_SHARES, inputs, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute decryption share challenge commitment.
/// This matches the Noir `compute_dec_share_challenge_commitment` function exactly.
/// Used in C6 (dec_share_trbfv circuit).
/// Takes a prepared payload (Vec<Field>) directly.
pub fn compute_dec_share_challenge_commitment(payload: Vec<Field>) -> BigInt {
    let commitment = compute_commitments(DS_CLG_DEC_SHARE, payload, 1);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}
