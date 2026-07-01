//! Falcon-512 public-key and signature byte codecs (M4-decode).
//!
//! Public key: header 0x09, then 512 coefficients × 14 bits, big-endian packed.
//! Signature:  header 0x39, 40-byte nonce, then s2 in Falcon "Compress" format
//!             (per coeff: sign bit, 7 low bits, high bits in unary + terminating 1).
//!
//! Validated by round-trip (decode∘encode == original) against real fn-dsa output,
//! which are the coefficients (h, s2) the Cairo verifier consumes.

pub const N: usize = 512;
pub const Q: u32 = 12289;
const PK_LEN: usize = 897;
const SIG_LEN: usize = 666;

// ---------- public key ----------

pub fn decode_pubkey(pk: &[u8]) -> Vec<u32> {
    assert_eq!(pk.len(), PK_LEN, "pubkey length");
    assert_eq!(pk[0], 0x09, "pubkey header (0x00|logn)");
    let mut coeffs = Vec::with_capacity(N);
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in &pk[1..] {
        acc = (acc << 8) | b as u32;
        bits += 8;
        if bits >= 14 {
            bits -= 14;
            let c = (acc >> bits) & 0x3FFF;
            assert!(c < Q, "pubkey coeff >= q");
            coeffs.push(c);
        }
    }
    assert_eq!(coeffs.len(), N);
    coeffs
}

pub fn encode_pubkey(coeffs: &[u32]) -> Vec<u8> {
    let mut out = vec![0x09u8];
    let (mut acc, mut bits) = (0u32, 0u32);
    for &c in coeffs {
        acc = (acc << 14) | (c & 0x3FFF);
        bits += 14;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    assert_eq!(bits, 0, "512*14 is byte-aligned");
    out
}

// ---------- signature ----------

fn bit(comp: &[u8], pos: usize) -> u32 {
    ((comp[pos / 8] >> (7 - (pos % 8))) & 1) as u32
}

/// Returns (nonce, s2 coefficients).
pub fn decode_signature(sig: &[u8]) -> (Vec<u8>, Vec<i32>) {
    assert_eq!(sig.len(), SIG_LEN, "signature length");
    assert_eq!(sig[0], 0x39, "sig header (0x30|logn)");
    let nonce = sig[1..41].to_vec();
    let comp = &sig[41..];
    let mut s2 = Vec::with_capacity(N);
    let mut pos = 0usize;
    for _ in 0..N {
        let sign = bit(comp, pos);
        pos += 1;
        let mut low = 0u32;
        for _ in 0..7 {
            low = (low << 1) | bit(comp, pos);
            pos += 1;
        }
        let mut k = 0u32;
        while bit(comp, pos) == 0 {
            k += 1;
            pos += 1;
            assert!(k < 2048, "unary run too long");
        }
        pos += 1; // terminating 1
        let mag = (k << 7) | low;
        assert!(!(sign == 1 && mag == 0), "negative zero forbidden");
        s2.push(if sign == 1 { -(mag as i32) } else { mag as i32 });
    }
    // trailing bits must be zero padding
    while pos < comp.len() * 8 {
        assert_eq!(bit(comp, pos), 0, "nonzero padding");
        pos += 1;
    }
    (nonce, s2)
}

pub fn encode_signature(nonce: &[u8], s2: &[i32]) -> Vec<u8> {
    let mut out = vec![0x39u8];
    out.extend_from_slice(nonce);
    let mut bits: Vec<u8> = Vec::new();
    for &c in s2 {
        bits.push(if c < 0 { 1 } else { 0 });
        let mag = c.unsigned_abs();
        for i in (0..7).rev() {
            bits.push(((mag >> i) & 1) as u8);
        }
        for _ in 0..(mag >> 7) {
            bits.push(0);
        }
        bits.push(1);
    }
    let total = (SIG_LEN - 41) * 8;
    assert!(bits.len() <= total, "compressed signature overflows");
    bits.resize(total, 0);
    for chunk in bits.chunks(8) {
        let mut byte = 0u8;
        for (i, &b) in chunk.iter().enumerate() {
            byte |= b << (7 - i);
        }
        out.push(byte);
    }
    out
}
