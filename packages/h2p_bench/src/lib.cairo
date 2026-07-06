//! Hash-to-point cost comparison for Falcon-512: SHAKE-256 vs Blake2s vs Poseidon.
//!
//! Each backend produces 512 coefficients in [0, q) from a fixed seed, using the
//! SAME acceptance rule (16-bit word < 5q  =>  coeff = word mod q), so the only
//! variable is the entropy source. Blake2s and Poseidon use the native Cairo
//! builtins; SHAKE-256 uses our pure-Cairo Keccak. These are non-standard
//! variants (like s2morrow's Poseidon) — measured for COST, not interop.
//!
//! Run one backend and print resources:
//!   scarb cairo-run --function h2p_blake2_run   --print-resource-usage
//!   scarb cairo-run --function h2p_poseidon_run --print-resource-usage
//!   scarb cairo-run --function h2p_shake_run    --print-resource-usage

use core::blake::blake2s_finalize;
use core::poseidon::hades_permutation;
use falcon::hash_to_point::hash_to_point;

const FIVE_Q: u32 = 61445; // 5q — rejection threshold
const Q32: u32 = 12289;
const Q128: u128 = 12289;

// ----------------------------------------------------------------- Blake2s XOF
// Standard Blake2s-256 initial state (IV with param 0x01010020 folded into s0).
fn blake_iv() -> Box<[u32; 8]> {
    BoxTrait::new(
        [0x6b08e647, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
         0x5be0cd19],
    )
}

/// Counter-mode XOF: block_i = Blake2s(seed15 || i); reject-sample to 512 coeffs.
pub fn h2p_blake2() -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut i: u32 = 0;
    while out.len() != 512 {
        // 16-word message block: 15 fixed seed words + the counter
        let msg = BoxTrait::new(
            [
                0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, 0x10111213, 0x14151617, 0x18191a1b,
                0x1c1d1e1f, 0x20212223, 0x24252627, 0x28292a2b, 0x2c2d2e2f, 0x30313233, 0x34353637,
                0x38393a3b, i,
            ],
        );
        let digest = blake2s_finalize(blake_iv(), 64, msg).unbox();
        let ds = digest.span();
        let mut k: u32 = 0;
        while k != 8 {
            let w = *ds.at(k);
            let hi = w / 65536;
            let lo = w % 65536;
            if hi < FIVE_Q && out.len() != 512 {
                out.append((hi % Q32).into());
            }
            if lo < FIVE_Q && out.len() != 512 {
                out.append((lo % Q32).into());
            }
            k += 1;
        }
        i += 1;
    }
    out
}

// --------------------------------------------------------------- Poseidon squeeze
/// Sponge squeeze over the Hades permutation; base-q extraction of coeffs (18
/// per felt via u128 halves), like s2morrow's PoseidonHashToPoint.
pub fn h2p_poseidon() -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut s0: felt252 = 'falcon-h2p-seed';
    let mut s1: felt252 = 0;
    let mut s2: felt252 = 0;
    while out.len() != 512 {
        let (r0, r1, r2) = hades_permutation(s0, s1, s2);
        extract_from_felt(r0, ref out);
        extract_from_felt(r1, ref out);
        s0 = r0;
        s1 = r1;
        s2 = r2;
    }
    out
}

fn extract_from_felt(f: felt252, ref out: Array<felt252>) {
    let x: u256 = f.into();
    let mut lo = x.low;
    let mut j: u32 = 0;
    while j != 9 && out.len() != 512 {
        out.append((lo % Q128).into());
        lo = lo / Q128;
        j += 1;
    }
    let mut hi = x.high;
    let mut k: u32 = 0;
    while k != 9 && out.len() != 512 {
        out.append((hi % Q128).into());
        hi = hi / Q128;
        k += 1;
    }
}

// ----------------------------------------------------------------- run harnesses
fn checksum(coeffs: Array<felt252>) -> felt252 {
    assert!(coeffs.len() == 512, "must be 512 coeffs");
    let mut s: felt252 = 0;
    let mut i: u32 = 0;
    while i != 512 {
        s += *coeffs.at(i);
        i += 1;
    }
    s
}

pub fn h2p_blake2_run() -> felt252 {
    checksum(h2p_blake2())
}

pub fn h2p_poseidon_run() -> felt252 {
    checksum(h2p_poseidon())
}

pub fn h2p_shake_run() -> felt252 {
    // 45-byte fixed input (40-byte nonce style + message)
    let mut input: Array<u8> = array![];
    let mut i: u32 = 0;
    while i != 45 {
        input.append((i % 251).try_into().unwrap());
        i += 1;
    }
    let coeffs = hash_to_point(input); // Array<u16>
    assert!(coeffs.len() == 512, "must be 512 coeffs");
    let mut s: felt252 = 0;
    let mut j: u32 = 0;
    while j != 512 {
        let c: felt252 = (*coeffs.at(j)).into();
        s += c;
        j += 1;
    }
    s
}
