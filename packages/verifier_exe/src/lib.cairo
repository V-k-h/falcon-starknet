//! Executable entry point to run the full Falcon-512 verify (both NTTs in-line)
//! via `scarb cairo-run`, which uses a different compiler path than snforge's
//! universal-sierra-compiler (that hit the offset/cast limits).
//!
//! `main` takes base-Q PACKED inputs (4 x 29 = 116 felts, ~17.66x smaller than
//! the 2048-felt unpacked form) and unpacks on-chain before verifying.
use falcon::verify::{
    verify_hint_512_packed, verify_hint_512_packed_looped, verify_full_shake, verify_full_from_pk,
};

/// Unrolled NTT — cheap in steps but NOT deployable (over the class-size cap).
/// Run: `scarb execute --executable-name verify_unrolled --print-resource-usage`
#[executable]
fn main(
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
    msg_point: Array<felt252>,
) -> bool {
    verify_hint_512_packed(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
}

/// Looped NTT — deployable (fits the cap). Same result. Measured in Cairo STEPS
/// here to compare apples-to-apples with published step counts.
/// Run: `scarb execute --executable-name verify_looped --print-resource-usage`
#[executable]
fn main_looped(
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
    msg_point: Array<felt252>,
) -> bool {
    verify_hint_512_packed_looped(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
}

/// Self-contained standard Falcon-512 verify: hashes the FN-DSA framed bytes
/// (nonce ‖ SHAKE256(pk)[0..64] ‖ 0x00 ‖ 0x00 ‖ message) to the challenge point
/// ON-CHAIN via interoperable SHAKE-256, then verifies (looped NTT). Measures the
/// true cost of a standard verifier; the pure-Cairo SHAKE dominates.
/// Run: `scarb execute --executable-name verify_full_shake --print-resource-usage`
#[executable]
fn main_full_shake(
    framed: Array<u8>,
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
) -> bool {
    verify_full_shake(framed, s2.span(), pk_ntt.span(), mul_hint.span())
}

/// Fully self-contained from the RAW public key: computes hpk = SHAKE256(pk)[0:64]
/// on-chain, builds the framed input, hashes to the challenge, and verifies.
/// Run: `scarb execute --executable-name verify_full_pk --print-resource-usage`
#[executable]
fn main_full_from_pk(
    vrfy_key: Array<u8>,
    nonce: Array<u8>,
    message: Array<u8>,
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
) -> bool {
    verify_full_from_pk(
        vrfy_key, nonce, message, s2.span(), pk_ntt.span(), mul_hint.span(),
    )
}
