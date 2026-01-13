use crate::packing::flatten;
use crate::utils::compute_safe;
use ark_bn254::Fr as Field;
use ark_bn254::Fr as FieldElement;
use ark_ff::BigInteger;
use ark_ff::PrimeField;
use num_bigint::BigInt;
use num_traits::Zero;

/// Compute a commitment to the public key polynomials by flattening them and hashing.
/// This matches the Noir `commitment_payload` and `generate_challenge` functions exactly.
pub fn compute_pk_commitment(pk0: &[Vec<BigInt>], pk1: &[Vec<BigInt>], bit_pk: u32) -> BigInt {
    // Step 1: Flatten pk0is and pk1is (matches commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, pk0, bit_pk);
    inputs = flatten(inputs, pk1, bit_pk);

    // Step 2: Hash using SafeSponge (matches generate_challenge in Noir)
    let domain_separator: [u8; 64] = [
        0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // IO Pattern: ABSORB(input_size), SQUEEZE(1)
    let input_size = inputs.len() as u32;
    let io_pattern = [0x80000000 | input_size, 1];

    let commitment = compute_safe(domain_separator, inputs, io_pattern);

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
    // Domain separator - "PVSS_pk_bfv" (must match BFV encryption circuit)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x70, 0x6b, 0x5f, 0x62, 0x66, 0x76, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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
    // Domain separator - "PVSS_pk_trbfv" (must match TRBFV public key circuit)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x70, 0x6b, 0x5f, 0x74, 0x72, 0x62, 0x66, 0x76, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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

/// Compute a commitment to the secret key polynomial by flattening it and hashing.
/// This matches the Noir `compute_sk_commitment` function exactly.
pub fn compute_sk_commitment(sk: &[BigInt], bit_sk: u32) -> BigInt {
    // Step 1: Flatten sk (matches sk_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[sk.to_vec()], bit_sk);

    // Step 2: Hash using SafeSponge (matches compute_sk_commitment in Noir)
    // Domain separator - "PVSS_sk_comm" (must match BFV public key circuit)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x6b, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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

/// Compute a commitment to the secret (either sk_trbfv or e_sm).
/// This matches the Noir `compute_secret_commitment` function exactly.
/// Used in C1, C2.
pub fn compute_secret_commitment(secret: &[BigInt], bit_secret: u32) -> BigInt {
    // Step 1: Flatten secret (matches prepare_single_polynomial_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[secret.to_vec()], bit_secret);

    // Step 2: Hash using SafeSponge (matches compute_secret_commitment in Noir)
    // Domain separator - "PVSS_secret" (must match C1 and C2)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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

/// Compute aggregated commitment for s or e
/// This matches the circuit's compute_aggregated_commitment function exactly
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

    // Domain separator - "PVSS_agg_sh" (must match BFV decryption circuit)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x61, 0x67, 0x67, 0x5f, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    let input_size = inputs.len();
    let io_pattern = [0x80000000 | input_size as u32, 0x00000001];

    let commitment = compute_safe(domain_separator, inputs, io_pattern);
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to the message polynomial.
pub fn compute_message_commitment(message: &[BigInt]) -> BigInt {
    // Convert message coefficients to Field (matches compute_message_commitment in Noir)
    // In Noir, message.coefficients[i] are Field values, so we convert BigInt to Field
    let inputs: Vec<FieldElement> = message.iter().map(crate::utils::bigint_to_field).collect();

    // Step 2: Hash using SafeSponge (matches compute_message_commitment in Noir)
    // Domain separator - "PVSS_sh_pm" (must match SK shares circuit)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x5f, 0x70, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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

/// Compute a commitment to shares for a specific party and modulus.
/// This matches the Noir `compute_shares_party_modulus_commitment` function exactly.
/// Used in C2 (verify shares circuit).
/// Takes a prepared payload from `prepare_shares_party_modulus_commitment_payload`.
pub fn compute_shares_party_modulus_commitment_from_payload(payload: Vec<Field>) -> BigInt {
    // Hash using SafeSponge (matches compute_shares_party_modulus_commitment in Noir)
    // Domain separator - "PVSS_sh_pm" (shares party-modulus)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x5f, 0x70, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // IO Pattern: ABSORB(input_size), SQUEEZE(1)
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 0x00000001];

    let commitment = compute_safe(domain_separator, payload, io_pattern);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute a commitment to a single polynomial (shares party-modulus commitment).
/// This matches the Noir `compute_shares_party_modulus_commitment` function exactly.
/// Used in C3 (message), C4 (single polynomial).
/// Takes a single polynomial and uses flatten with BIT_MSG for packing.
/// For C2 (verify shares), use `prepare_shares_party_modulus_commitment_payload` + `compute_shares_party_modulus_commitment_from_payload` instead.
pub fn compute_shares_party_modulus_commitment(share: &[BigInt], bit_msg: u32) -> BigInt {
    // Step 1: Flatten share (matches prepare_single_polynomial_commitment_payload in Noir)
    let mut inputs: Vec<Field> = Vec::new();
    inputs = flatten(inputs, &[share.to_vec()], bit_msg);

    // Step 2: Hash using SafeSponge (matches compute_shares_party_modulus_commitment in Noir)
    // Domain separator - "PVSS_sh_pm" (shares party-modulus)
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x73, 0x68, 0x5f, 0x70, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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

/// Compute Greco pk aggregation commitment.
/// This matches the Noir `compute_greco_pk_agg_commitment` function exactly.
/// Used in Greco circuit, C5.
/// Takes a prepared payload (Vec<Field>) directly.
pub fn compute_greco_pk_agg_commitment(payload: Vec<Field>) -> BigInt {
    // Domain separator - "Greco"
    let domain_separator: [u8; 64] = [
        0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // IO Pattern: ABSORB(input_size), SQUEEZE(1)
    let input_size = payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, 0x00000001];

    let commitment = compute_safe(domain_separator, payload, io_pattern);

    // Convert Field to BigInt
    let commitment_field = commitment[0];
    let commitment_bytes = commitment_field.into_bigint().to_bytes_le();
    BigInt::from_bytes_le(num_bigint::Sign::Plus, &commitment_bytes)
}

/// Compute Greco challenge commitment.
/// This matches the Noir `compute_greco_challenge_commitment` function exactly.
/// Used in Greco circuit.
/// Verifies pk_commitment using commitment_payload, then generates challenges from gammas_payload.
pub fn compute_greco_challenge_commitment(
    commitment_payload: Vec<Field>,
    gammas_payload: Vec<Field>,
    pk_commitment: &BigInt,
    l: usize,
) -> Vec<BigInt> {
    // Verify pk_commitment matches the commitment from commitment_payload
    let computed_pk_commitment = compute_greco_pk_agg_commitment(commitment_payload);
    if computed_pk_commitment != *pk_commitment {
        panic!(
            "PK commitment mismatch in Greco circuit: expected {}, got {}",
            pk_commitment, computed_pk_commitment
        );
    }

    // Domain separator - "Greco"
    let domain_separator: [u8; 64] = [
        0x47, 0x72, 0x65, 0x63, 0x6f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];

    // IO Pattern: ABSORB(input_size), SQUEEZE(2*L)
    let input_size = gammas_payload.len() as u32;
    let io_pattern = [0x80000000 | input_size, (2 * l as u32)];

    let challenges = compute_safe(domain_separator, gammas_payload, io_pattern);

    // Convert Fields to BigInts
    challenges
        .into_iter()
        .map(|challenge_field| {
            let challenge_bytes = challenge_field.into_bigint().to_bytes_le();
            BigInt::from_bytes_le(num_bigint::Sign::Plus, &challenge_bytes)
        })
        .collect()
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
    // Domain separator - "PVSS_agg_sh"
    let domain_separator: [u8; 64] = [
        0x50, 0x56, 0x53, 0x53, 0x5f, 0x61, 0x67, 0x67, 0x5f, 0x73, 0x68, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
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
