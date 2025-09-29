//! PK PVW circuit parameter generation for zero-knowledge FHE proofs
//!
//! Verifies that a PVW public key was correctly generated according to the protocol.
//! For each party i and modulus l, the public key generation equation is:
//!  b_{l,i} = a_l * s_i + e_i + r2_{l,i} * (X^N + 1) + r1_{l,i} * q_l
//!
//! Where:
//! - a_l is the l-th KxK CRS matrix (same for all parties)
//! - s_i is party i's secret key (K-dimensional vector of polynomials)
//! - e_i is party i's error vector (K-dimensional, small coefficients)
//! - b_{l,i} is party i's public key for modulus l (K-dimensional vector)
//! - r1_{l,i}, r2_{l,i} are quotients from modulus switching and cyclotomic reduction
//! - L is the number of moduli, must equal the length of QIS array
//! - q_l = QIS[l] is the l-th modulus in the RNS representation
pub mod bounds;
pub mod circuit;
pub mod sample;
pub mod template;
pub mod toml;
pub mod vectors;
