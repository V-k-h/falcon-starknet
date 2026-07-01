//! Executable entry point to run the full Falcon-512 verify (both NTTs in-line)
//! via `scarb cairo-run`, which uses a different compiler path than snforge's
//! universal-sierra-compiler (that hit the offset/cast limits).
use falcon::verify::verify_hint_512;

fn main(
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
    msg_point: Array<felt252>,
) -> bool {
    verify_hint_512(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
}
