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

use crate::ntt_generated::ntt_4;

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

/// Verify a hint-based Falcon proof for n=4. Returns true iff accepted.
pub fn verify_hint_4(
    s2: Span<felt252>,
    pk_ntt: Span<felt252>,
    mul_hint: Span<felt252>,
    msg_point: Span<felt252>,
) -> bool {
    // (1) hint consistency: NTT(mul_hint) == NTT(s2) ∘ pk_ntt
    let a = ntt_4(s2);
    let b = ntt_4(mul_hint);
    let mut i: u32 = 0;
    while i != 4 {
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
    while j != 4 {
        let mp = to_u64(*msg_point.at(j));
        let mh = to_u64(*mul_hint.at(j));
        let s1 = (mp + Q - mh) % Q;
        norm += center_sq(s1);
        norm += center_sq(to_u64(*s2.at(j)));
        j += 1;
    }
    norm <= SIG_BOUND_512
}
