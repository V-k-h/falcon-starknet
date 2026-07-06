//! Falcon verification core — hint-based (2 NTTs, 0 INTTs).
//!
//! Given the signature's short polynomial s2, the public key in NTT domain
//! (pk_ntt = NTT(h)), the signer-supplied product hint (mul_hint = s2·h), and the
//! challenge point (msg_point = hash_to_point output), verification:
//!   1. checks the hint: NTT(mul_hint) == NTT(s2) ∘ pk_ntt   (so mul_hint = s2·h)
//!   2. recovers s1 = msg_point − mul_hint  (mod q)
//!   3. accepts iff ‖s1‖² + ‖s2‖² ≤ B     (centered coefficients)
//!
//! SEED SCOPE (M4): n=4 wiring, validated end-to-end with a self-consistent
//! vector. Same logic at n=512 once the NTT-512 snforge/Sierra-cost limit is
//! resolved (M2-opt); decoding real fn-dsa signature/pubkey bytes is M4-decode.

use crate::ntt512::ntt_512;
use crate::ntt_looped::ntt_512_looped;
use crate::ntt_generated::ntt_4;
use crate::packing::unpack_512;
use crate::hash_to_point::hash_to_point;
use crate::shake256::shake256_lanes;

const Q: u64 = 12289;
const HALF_Q: u64 = 6144; // ⌊q/2⌋
/// Falcon-512 squared L2 acceptance bound (l2bound[9]).
pub const SIG_BOUND_512: u64 = 34034726;

fn to_u64(x: felt252) -> u64 {
    let u: u128 = x.try_into().unwrap();
    u.try_into().unwrap()
}

/// |center(x)|² for x in [0,q): map to [-⌊q/2⌋, ⌊q/2⌋], return the square.
fn center_sq(x: u64) -> u64 {
    let c = if x > HALF_Q {
        Q - x
    } else {
        x
    };
    c * c
}

/// Core check given a = NTT(s2), b = NTT(mul_hint) (transform size = n).
pub fn verify_core(
    s2: Span<felt252>,
    pk_ntt: Span<felt252>,
    mul_hint: Span<felt252>,
    msg_point: Span<felt252>,
    a: Span<felt252>,
    b: Span<felt252>,
    n: u32,
) -> bool {
    // (1) hint consistency: NTT(mul_hint) == NTT(s2) ∘ pk_ntt
    let mut i: u32 = 0;
    while i != n {
        let ai: u128 = (*a.at(i)).try_into().unwrap();
        let pki: u128 = (*pk_ntt.at(i)).try_into().unwrap();
        let bi: u128 = (*b.at(i)).try_into().unwrap();
        if (ai * pki) % 12289 != bi {
            return false;
        }
        i += 1;
    }
    // (2)+(3) s1 = msg_point − mul_hint (mod q); norm = Σ center(s1)² + center(s2)²
    let mut norm: u64 = 0;
    let mut j: u32 = 0;
    while j != n {
        let s1 = (to_u64(*msg_point.at(j)) + Q - to_u64(*mul_hint.at(j))) % Q;
        norm += center_sq(s1);
        norm += center_sq(to_u64(*s2.at(j)));
        j += 1;
    }
    norm <= SIG_BOUND_512
}

/// Hint-based verify, n=4 (self-consistent test vector).
pub fn verify_hint_4(
    s2: Span<felt252>, pk_ntt: Span<felt252>, mul_hint: Span<felt252>, msg_point: Span<felt252>,
) -> bool {
    let a = ntt_4(s2);
    let b = ntt_4(mul_hint);
    verify_core(s2, pk_ntt, mul_hint, msg_point, a.span(), b.span(), 4)
}

/// Hint-based verify, n=512 (full Falcon-512).
pub fn verify_hint_512(
    s2: Span<felt252>, pk_ntt: Span<felt252>, mul_hint: Span<felt252>, msg_point: Span<felt252>,
) -> bool {
    let a = ntt_512(s2);
    let b = ntt_512(mul_hint);
    verify_core(s2, pk_ntt, mul_hint, msg_point, a.span(), b.span(), 512)
}

/// Hint-based verify, n=512, using the DEPLOYABLE looped NTT. Identical result
/// to `verify_hint_512` (the looped NTT is bit-for-bit equal to the unrolled
/// one) but its compact code fits Starknet's contract class-size cap, so this is
/// the entrypoint a real on-chain verifier uses.
pub fn verify_hint_512_looped(
    s2: Span<felt252>, pk_ntt: Span<felt252>, mul_hint: Span<felt252>, msg_point: Span<felt252>,
) -> bool {
    let a = ntt_512_looped(s2);
    let b = ntt_512_looped(mul_hint);
    verify_core(s2, pk_ntt, mul_hint, msg_point, a.span(), b.span(), 512)
}

/// SELF-CONTAINED verify: computes the challenge on-chain from the FN-DSA framed
/// bytes (nonce ‖ SHAKE256(pk)[0..64] ‖ 0x00 ‖ 0x00 ‖ message) via interoperable
/// SHAKE-256 hash-to-point, then runs the looped-NTT verify. This is the true
/// standard Falcon-512 verifier — no pre-hashed msg_point is trusted from the
/// caller. Interoperable, but the pure-Cairo SHAKE dominates cost (see docs):
/// this is a measurement/reference path, expected to exceed on-chain limits until
/// a keccak_f1600 syscall (SNIP-32) exists.
pub fn verify_full_shake(
    framed: Array<u8>, s2: Span<felt252>, pk_ntt: Span<felt252>, mul_hint: Span<felt252>,
) -> bool {
    let c = hash_to_point(framed); // Array<u16>, 512 challenge coeffs in [0,q)
    let mut msg_point: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 512 {
        msg_point.append((*c.at(i)).into());
        i += 1;
    }
    verify_hint_512_looped(s2, pk_ntt, mul_hint, msg_point.span())
}

/// Rebuild the FN-DSA hash-to-point input entirely on-chain from the RAW public
/// key, computing hpk = SHAKE256(vrfy_key)[0..64] here (no off-chain precompute):
///   framed = nonce ‖ hpk ‖ 0x00 ‖ 0x00 ‖ message.
/// The 64 hpk bytes are the first 8 SHAKE lanes, little-endian per lane — exactly
/// the byte order the reference's XOF reader produces.
pub fn build_framed(
    vrfy_key: Array<u8>, nonce: Array<u8>, message: Array<u8>,
) -> Array<u8> {
    let hpk = shake256_lanes(vrfy_key, 8); // 8 lanes = 64 bytes

    let mut framed: Array<u8> = array![];
    let mut i: u32 = 0;
    while i != nonce.len() {
        framed.append(*nonce.at(i));
        i += 1;
    }
    // hpk lanes -> little-endian bytes
    let mut li: u32 = 0;
    while li != 8 {
        let mut lane: u64 = *hpk.at(li);
        let mut bpos: u32 = 0;
        while bpos != 8 {
            framed.append((lane % 256).try_into().unwrap());
            lane = lane / 256;
            bpos += 1;
        }
        li += 1;
    }
    framed.append(0); // DOMAIN_NONE
    framed.append(0); // empty context length
    let mut j: u32 = 0;
    while j != message.len() {
        framed.append(*message.at(j));
        j += 1;
    }
    framed
}

/// Fully self-contained verify from the RAW public key: computes hpk on-chain
/// (SHAKE256 over the encoded pubkey), builds the FN-DSA framed input, hashes it
/// to the challenge (SHAKE256 hash-to-point), then runs the looped-NTT verify.
/// Nothing hash-related is trusted from off-chain.
pub fn verify_full_from_pk(
    vrfy_key: Array<u8>,
    nonce: Array<u8>,
    message: Array<u8>,
    s2: Span<felt252>,
    pk_ntt: Span<felt252>,
    mul_hint: Span<felt252>,
) -> bool {
    let framed = build_framed(vrfy_key, nonce, message);
    verify_full_shake(framed, s2, pk_ntt, mul_hint)
}

/// Hint-based verify with base-Q packed inputs (29 felts each, ~17.66x smaller
/// calldata). Unpacks the four polynomials, then runs `verify_hint_512`. This
/// trades L1 calldata (2048 -> 116 felts) for the on-chain unpack compute.
pub fn verify_hint_512_packed(
    s2_p: Span<felt252>,
    pk_ntt_p: Span<felt252>,
    mul_hint_p: Span<felt252>,
    msg_point_p: Span<felt252>,
) -> bool {
    let s2 = unpack_512(s2_p);
    let pk_ntt = unpack_512(pk_ntt_p);
    let mul_hint = unpack_512(mul_hint_p);
    let msg_point = unpack_512(msg_point_p);
    verify_hint_512(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
}

/// Same as `verify_hint_512_packed` but with the DEPLOYABLE looped NTT — this is
/// the packed entrypoint measurable in Cairo STEPS via `scarb cairo-run`.
pub fn verify_hint_512_packed_looped(
    s2_p: Span<felt252>,
    pk_ntt_p: Span<felt252>,
    mul_hint_p: Span<felt252>,
    msg_point_p: Span<felt252>,
) -> bool {
    let s2 = unpack_512(s2_p);
    let pk_ntt = unpack_512(pk_ntt_p);
    let mul_hint = unpack_512(mul_hint_p);
    let msg_point = unpack_512(msg_point_p);
    verify_hint_512_looped(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
}
