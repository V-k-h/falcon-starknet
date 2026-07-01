use falcon::ntt_generated::ntt_128;

// Differential test: the codegen'd NTT must match the Rust reference
// (falcon-codegen::ntt::ntt_fast_ref) on input a_i = (41*i + 7) mod q.
// Validated at n=128 (snforge-compilable). The Rust suite proves the transform
// is correct (convolution property) and felt252-safe up to n=512.

#[test]
fn ntt_128_matches_reference() {
    let mut input: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 128 {
        let v: u32 = (i * 41 + 7) % 12289;
        input.append(v.into());
        i += 1;
    }

    let out = ntt_128(input.span());
    assert!(out.len() == 128, "128 outputs");

    // spot-checks (bit-reversed order, matching the reference)
    assert!(*out.at(0) == 5271, "out0");
    assert!(*out.at(1) == 5647, "out1");
    assert!(*out.at(63) == 6880, "out63");
    assert!(*out.at(127) == 10269, "out127");

    // full-vector checksum
    let mut s: u64 = 0;
    let mut j: u32 = 0;
    while j != 128 {
        let cu: u128 = (*out.at(j)).try_into().unwrap();
        s += cu.try_into().unwrap();
        j += 1;
    }
    assert!(s == 775103, "checksum of all 128 outputs");
}
