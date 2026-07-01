use falcon::zq::{add_mod, sub_mod, mul_mod};

#[test]
fn zq_add_wraps() {
    assert!(add_mod(12288, 1) == 0, "12288+1 == 0 mod q");
    assert!(add_mod(5, 7) == 12, "5+7");
}

#[test]
fn zq_sub_underflow() {
    assert!(sub_mod(0, 1) == 12288, "0-1 == q-1");
    assert!(sub_mod(7, 5) == 2, "7-5");
}

#[test]
fn zq_mul_reduces() {
    // (q-1)*2 = 24576 ; 24576 mod 12289 = 12287
    assert!(mul_mod(12288, 2) == 12287, "(q-1)*2");
    assert!(mul_mod(0, 5) == 0, "0*5");
}
