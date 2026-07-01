use falcon::hash_to_point::hash_to_point;

// Oracle: Python hashlib.shake_256 + Falcon rejection sampling.
// input = bytes(0..40) ‖ "hello".
fn kat_input() -> Array<u8> {
    array![
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
    ]
}

#[test]
fn hash_to_point_kat() {
    let c = hash_to_point(kat_input());
    assert!(c.len() == 512, "must produce 512 coefficients");

    // first 8 coefficients
    assert!(*c.at(0) == 12001, "c0");
    assert!(*c.at(1) == 12076, "c1");
    assert!(*c.at(2) == 7887, "c2");
    assert!(*c.at(3) == 3995, "c3");
    assert!(*c.at(4) == 11053, "c4");
    assert!(*c.at(5) == 10629, "c5");
    assert!(*c.at(6) == 8937, "c6");
    assert!(*c.at(7) == 6892, "c7");

    // last coefficient
    assert!(*c.at(511) == 170, "c511");

    // full-vector checksum
    let mut s: u64 = 0;
    let mut i: u32 = 0;
    while i != 512 {
        s += (*c.at(i)).into();
        i += 1;
    }
    assert!(s == 3097825, "sum of all 512 coefficients");
}
