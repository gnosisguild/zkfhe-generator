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
