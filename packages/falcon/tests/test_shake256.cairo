use falcon::shake256::shake256_lanes;

// Oracles from Python hashlib.shake_256 (little-endian 64-bit lanes).

#[test]
fn shake_empty() {
    let msg: Array<u8> = array![];
    let out = shake256_lanes(msg, 5);
    assert!(*out.at(0) == 0x138da80b2bddb946, "lane0");
    assert!(*out.at(1) == 0x24eb3e74eb3f3b23, "lane1");
    assert!(*out.at(2) == 0x821bb862ea52cd3f, "lane2");
    assert!(*out.at(3) == 0x2f76d56e64270cb5, "lane3");
    assert!(*out.at(4) == 0x00f2c0d8ddc45dd7, "lane4");
}

#[test]
fn shake_abc() {
    let msg: Array<u8> = array![0x61, 0x62, 0x63];
    let out = shake256_lanes(msg, 5);
    assert!(*out.at(0) == 0x77a8601360663348, "lane0");
    assert!(*out.at(1) == 0x4d11c40c0863681c, "lane1");
    assert!(*out.at(2) == 0xeee1f1f83045b48d, "lane2");
    assert!(*out.at(3) == 0x39578be737ea944f, "lane3");
    assert!(*out.at(4) == 0x86536a18ef5ba1d5, "lane4");
}

#[test]
fn shake_abc_multiblock_squeeze() {
    // 18 lanes forces a second squeeze permutation; lane17 is block-2 lane0.
    let msg: Array<u8> = array![0x61, 0x62, 0x63];
    let out = shake256_lanes(msg, 18);
    assert!(*out.at(17) == 0x581affee10a60ecf, "lane17 (2nd squeeze block)");
}
