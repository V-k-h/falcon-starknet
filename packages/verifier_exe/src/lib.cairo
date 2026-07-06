//! Executable entry point to run the full Falcon-512 verify (both NTTs in-line)
//! via `scarb cairo-run`, which uses a different compiler path than snforge's
//! universal-sierra-compiler (that hit the offset/cast limits).
//!
//! `main` takes base-Q PACKED inputs (4 x 29 = 116 felts, ~17.66x smaller than
//! the 2048-felt unpacked form) and unpacks on-chain before verifying.
use falcon::verify::verify_hint_512_packed;

fn main(
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
    msg_point: Array<felt252>,
) -> bool {
    verify_hint_512_packed(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
}
