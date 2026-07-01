use falcon::verify::verify_hint_4;

// Self-consistent n=4 vector from falcon-codegen (verify_vec::print_verify4):
//   s1 = [1,-2,0,1], s2 = [2,1,-1,0], h = [3,5,7,11]
//   mul_hint = s2·h, msg_point = s1 + mul_hint, pk_ntt = NTT(h), norm = 12.
fn s2() -> Span<felt252> {
    array![2, 1, 12288, 0].span()
}
fn pk_ntt() -> Span<felt252> {
    array![9880, 10832, 7774, 8393].span()
}
fn mul_hint() -> Span<felt252> {
    array![2, 24, 16, 24].span()
}
fn msg_point() -> Span<felt252> {
    array![3, 22, 16, 25].span()
}

#[test]
fn verify_accepts_valid() {
    assert!(verify_hint_4(s2(), pk_ntt(), mul_hint(), msg_point()), "valid proof must accept");
}

#[test]
fn verify_rejects_tampered_hint() {
    // corrupt one mul_hint coefficient → NTT(mul_hint) ≠ NTT(s2)∘pk_ntt
    let bad = array![3, 24, 16, 24].span();
    assert!(!verify_hint_4(s2(), pk_ntt(), bad, msg_point()), "bad hint must reject");
}

#[test]
fn verify_rejects_large_norm() {
    // shift msg_point[0] so s1[0] ≈ 6000 → norm ≈ 3.6e7 > bound (hint still consistent)
    let mp = array![6002, 22, 16, 25].span();
    assert!(!verify_hint_4(s2(), pk_ntt(), mul_hint(), mp), "oversized norm must reject");
}
