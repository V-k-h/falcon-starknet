//! Falcon hash-to-point: SHAKE256(input) → 512 coefficients in Z_q via rejection
//! sampling. This is the cost-critical path (pure-Cairo Keccak; ~10 permutations).
//!
//! Algorithm (Falcon spec): read the SHAKE output as a byte stream, take 16-bit
//! big-endian words, reject any word ≥ 5·q, else accept (word mod q). Repeat to
//! 512 coefficients.
//!
//! SEED SCOPE (M3): the caller supplies the exact absorbed bytes. Matching
//! FN-DSA's domain-separated input framing (nonce ‖ hpk ‖ ctx ‖ message) is wired
//! at end-to-end integration (M4) against the rust-fn-dsa reference.

use crate::shake256::shake256_lanes;
use crate::zq::Zq;

const Q32: u32 = 12289;
const FIVE_Q: u32 = 61445; // 5 * q — rejection threshold

/// 256^w for w in 0..=7 (byte selector within a 64-bit lane).
fn pow256(w: u32) -> u64 {
    match w {
        0 => 1,
        1 => 256,
        2 => 65536,
        3 => 16777216,
        4 => 4294967296,
        5 => 1099511627776,
        6 => 281474976710656,
        _ => 72057594037927936,
    }
}

/// Byte `idx` of the little-endian SHAKE output stream held as u64 lanes.
fn byte_of(lanes: @Array<u64>, idx: u32) -> u32 {
    let lane = *lanes.at(idx / 8);
    let within = idx % 8;
    let b: u64 = (lane / pow256(within)) % 256;
    b.try_into().unwrap()
}

/// Falcon hash-to-point over the given absorbed bytes → 512 Z_q coefficients.
pub fn hash_to_point(input: Array<u8>) -> Array<Zq> {
    // 160 lanes = 1280 bytes = 640 reads; mean ~600 accepts ≫ 512 (safe margin).
    let lanes = shake256_lanes(input, 160);

    let mut coeffs: Array<Zq> = array![];
    let mut b: u32 = 0;
    while coeffs.len() != 512 {
        let hi = byte_of(@lanes, b);
        let lo = byte_of(@lanes, b + 1);
        let elt: u32 = hi * 256 + lo;
        b += 2;
        if elt < FIVE_Q {
            let c: Zq = (elt % Q32).try_into().unwrap();
            coeffs.append(c);
        }
    }
    coeffs
}
