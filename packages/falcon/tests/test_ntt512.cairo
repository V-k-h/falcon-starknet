use falcon::ntt512::ntt_512;
use falcon::ntt_looped::ntt_512_looped;

// Full-size differential test against the Rust reference (ntt_fast_ref), input
// a_i = (41*i + 7) mod q. Lazy reduction (M2-opt) gives the same result as the
// reduce-every-layer version (reduction is a ring homomorphism).
#[test]
fn ntt_512_matches_reference() {
    let mut input: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 512 {
        let v: u32 = (i * 41 + 7) % 12289;
        input.append(v.into());
        i += 1;
    }

    let out = ntt_512(input.span());
    assert!(out.len() == 512, "512 outputs");
    assert!(*out.at(0) == 3814, "out0");
    assert!(*out.at(1) == 8975, "out1");
    assert!(*out.at(255) == 5041, "out255");
    assert!(*out.at(511) == 4004, "out511");

    let mut s: u64 = 0;
    let mut j: u32 = 0;
    while j != 512 {
        let cu: u128 = (*out.at(j)).try_into().unwrap();
        s += cu.try_into().unwrap();
        j += 1;
    }
    assert!(s == 3124990, "checksum of all 512 outputs");
}

// Standalone gas measurement of the deployable looped NTT (no unrolled call).
#[test]
fn ntt_512_looped_gas() {
    let mut input: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 512 {
        let v: u32 = (i * 41 + 7) % 12289;
        input.append(v.into());
        i += 1;
    }
    let out = ntt_512_looped(input.span());
    assert!(*out.at(0) == 3814, "out0");
    assert!(*out.at(511) == 4004, "out511");
}

// The DEPLOYABLE looped NTT must be bit-for-bit equal to the unrolled ntt_512
// (same twiddle table + CT structure). Same input as above; assert equality
// coefficient-by-coefficient so any divergence is caught immediately.
#[test]
fn ntt_512_looped_matches_unrolled() {
    let mut input: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 512 {
        let v: u32 = (i * 41 + 7) % 12289;
        input.append(v.into());
        i += 1;
    }

    let expected = ntt_512(input.span());
    let got = ntt_512_looped(input.span());
    assert!(got.len() == 512, "512 outputs");
    let mut j: u32 = 0;
    while j != 512 {
        assert!(*got.at(j) == *expected.at(j), "looped != unrolled at coeff");
        j += 1;
    }
}
