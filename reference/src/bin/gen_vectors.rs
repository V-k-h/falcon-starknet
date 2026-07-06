//! Generate an end-to-end Falcon-512 KAT from Pornin's FN-DSA reference.
//! Produces packages/falcon/tests/data/verify_kat.json — the M4 oracle for the
//! Cairo verifier (standard SHAKE256, so these are real interoperable signatures).

use fn_dsa::{
    signature_size, sign_key_size, vrfy_key_size, DOMAIN_NONE, FN_DSA_LOGN_512, HASH_ID_RAW,
    KeyPairGenerator, KeyPairGeneratorStandard, SigningKey, SigningKeyStandard, VerifyingKey,
    VerifyingKeyStandard,
};
use rand_core::OsRng;
use serde::Serialize;

#[derive(Serialize)]
struct VerifyKat {
    scheme: String,
    logn: u32,
    message_hex: String,
    vrfy_key_hex: String,
    signature_hex: String,
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn main() {
    let message = b"falcon-starknet KAT vector 0";

    // keygen
    let mut kg = KeyPairGeneratorStandard::default();
    let mut sign_key = [0u8; sign_key_size(FN_DSA_LOGN_512)];
    let mut vrfy_key = [0u8; vrfy_key_size(FN_DSA_LOGN_512)];
    kg.keygen(FN_DSA_LOGN_512, &mut OsRng, &mut sign_key, &mut vrfy_key);

    // sign
    let mut sk = SigningKeyStandard::decode(&sign_key).expect("decode sign key");
    let mut sig = vec![0u8; signature_size(sk.get_logn())];
    sk.sign(&mut OsRng, &DOMAIN_NONE, &HASH_ID_RAW, message, &mut sig);

    // verify (self-check the oracle)
    let vk = VerifyingKeyStandard::decode(&vrfy_key).expect("decode vrfy key");
    let ok = vk.verify(&sig, &DOMAIN_NONE, &HASH_ID_RAW, message);
    assert!(ok, "reference signature must verify");

    // ---- M4-decode: our byte codecs, validated by round-trip on real fn-dsa bytes ----
    use falcon_reference::falcon_codec::{decode_pubkey, decode_signature, encode_pubkey, encode_signature};
    let h = decode_pubkey(&vrfy_key);
    assert_eq!(encode_pubkey(&h), vrfy_key.to_vec(), "pubkey round-trip");
    assert!(h.iter().all(|&c| c < 12289), "h coeffs in [0,q)");

    let (nonce, s2) = decode_signature(&sig);
    assert_eq!(encode_signature(&nonce, &s2), sig, "signature round-trip");
    let max_s2 = s2.iter().map(|c| c.unsigned_abs()).max().unwrap();
    assert!(max_s2 < 2048, "s2 coeffs are short (Falcon Gaussian)");
    eprintln!("[gen-vectors] codec OK: h[0..3]={:?}, s2[0..3]={:?}, max|s2|={}", &h[0..3], &s2[0..3], max_s2);

    // ---- M4 e2e: reconstruct the hint-verify vector and check the norm bound in Rust ----
    // (a passing norm here proves FN-DSA hash framing + decode + product are all correct)
    use falcon_codegen::ntt::{negacyclic_mul, ntt_fast_ref};
    use sha3::digest::{ExtendableOutput, Update, XofReader};
    use sha3::Shake256;
    const QI: i128 = 12289;

    // hpk = SHAKE256(vrfy_key)[0..64]
    let mut shk = Shake256::default();
    shk.update(&vrfy_key);
    let mut xof = shk.finalize_xof();
    let mut hpk = [0u8; 64];
    xof.read(&mut hpk);

    // framed = nonce || hpk || 0x00 (raw) || 0x00 (empty ctx len) || message
    let mut framed = Vec::new();
    framed.extend_from_slice(&nonce);
    framed.extend_from_slice(&hpk);
    framed.push(0u8);
    framed.push(0u8);
    framed.extend_from_slice(message);

    // c = hash_to_point(framed): 2-byte BE, reject >= 5q, mod q, 512 coeffs
    let mut shk2 = Shake256::default();
    shk2.update(&framed);
    let mut r2 = shk2.finalize_xof();
    let mut c: Vec<i128> = Vec::with_capacity(512);
    let mut buf = [0u8; 2];
    while c.len() < 512 {
        r2.read(&mut buf);
        let mut w = ((buf[0] as i128) << 8) | (buf[1] as i128);
        if w < 61445 {
            w %= QI;
            c.push(w);
        }
    }

    let hh: Vec<i128> = h.iter().map(|&x| x as i128).collect();
    let s2i: Vec<i128> = s2.iter().map(|&x| x as i128).collect();
    let s2_stored: Vec<i128> = s2i.iter().map(|&x| ((x % QI) + QI) % QI).collect();
    let mul = negacyclic_mul(&s2i, &hh); // s2·h mod q
    let pk_ntt = ntt_fast_ref(&hh);

    let center = |x: i128| if x > QI / 2 { x - QI } else { x };
    let mut norm: i128 = 0;
    for i in 0..512 {
        let s1 = (((c[i] - mul[i]) % QI) + QI) % QI;
        let a = center(s1);
        let b = center(s2_stored[i]);
        norm += a * a + b * b;
    }
    eprintln!("[e2e] ||s1||^2+||s2||^2 = {}  (bound 34034726)", norm);
    assert!(norm <= 34_034_726, "real fn-dsa signature must satisfy the norm bound");
    eprintln!("[e2e] ✓ real Falcon-512 signature verifies (framing + decode + product correct)");

    // Precompute the two forward NTTs (Cairo's ntt_512 is proven equal to this in
    // test_ntt512; keeping them out of the verify test avoids compiling two 11k-line
    // NTT bodies into one CASM unit — the known s2morrow frame-offset limit).
    let a_ntt = ntt_fast_ref(&s2_stored);
    let b_ntt = ntt_fast_ref(&mul);

    // ---- emit the vector as snforge-loadable JSON (length-prefixed arrays) ----
    // Loaded via read_json at runtime (avoids inline-literal CASM frame overflow).
    let mut vals: Vec<i128> = Vec::new();
    for a in [&s2_stored, &pk_ntt, &mul, &c, &a_ntt, &b_ntt] {
        vals.push(a.len() as i128);
        vals.extend_from_slice(a);
    }
    let body: Vec<String> = vals.iter().map(|v| v.to_string()).collect();
    let json = format!("{{ \"verify512\": [{}] }}\n", body.join(", "));
    let jp = "../packages/falcon/tests/data/verify512_kat.json";
    std::fs::write(jp, json).expect("write json vector");
    eprintln!("[e2e] wrote {jp}");

    // cairo-run args: [[s2],[pk_ntt],[mul_hint],[msg_point]] for `scarb cairo-run`
    let arr_json = |a: &[i128]| -> String {
        format!("[{}]", a.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(","))
    };
    let args = format!(
        "[{},{},{},{}]\n",
        arr_json(&s2_stored), arr_json(&pk_ntt), arr_json(&mul), arr_json(&c),
    );
    let ap = "../packages/falcon/tests/data/verify512_args.json";
    std::fs::write(ap, args).expect("write args");
    eprintln!("[e2e] wrote {ap}");

    // ---- pq-verifiers fixture: base-Q pack (18 coeffs/felt) -> 29 felts each ----
    // Direct-NTT encoding: public_key = pack(h) [29], signature = pack(s2) ++ pack(msg_point) [58].
    use num_bigint::BigUint;
    let pack = |vals: &[i128]| -> Vec<String> {
        let q = BigUint::from(12289u32);
        let mut felts = Vec::new();
        for chunk in vals.chunks(18) {
            let mut acc = BigUint::from(0u32);
            for &v in chunk.iter().rev() {
                acc = &acc * &q + BigUint::from(v as u64);
            }
            felts.push(acc.to_str_radix(10));
        }
        felts
    };
    let h_i: Vec<i128> = h.iter().map(|&x| x as i128).collect();
    let pk_felts = pack(&h_i);
    let mut sig_felts = pack(&s2_stored);
    sig_felts.extend(pack(&c));
    let fixture = format!(
        "// pubkey ({} felts) = base-Q pack(h);  signature ({} felts) = pack(s2) ++ pack(msg_point)\nPUBKEY: [{}]\nSIG: [{}]\n",
        pk_felts.len(), sig_felts.len(), pk_felts.join(", "), sig_felts.join(", "),
    );
    // packed cairo-run args for the hint verifier: [[pack(s2)],[pack(pk_ntt)],[pack(mul)],[pack(c)]]
    let pj = |a: &[i128]| format!("[{}]", pack(a).join(","));
    let packed_args = format!(
        "[{},{},{},{}]\n", pj(&s2_stored), pj(&pk_ntt), pj(&mul), pj(&c),
    );
    std::fs::write("../packages/falcon/tests/data/verify512_packed_args.json", packed_args)
        .expect("write packed args");
    eprintln!("[e2e] wrote verify512_packed_args.json (4 x 29 = 116 packed felts)");

    let fp = "../packages/falcon/tests/data/pqbench_fixture.txt";
    std::fs::write(fp, &fixture).expect("write fixture");
    eprintln!("[e2e] wrote {fp}  (pubkey {} felts, signature {} felts)", pk_felts.len(), sig_felts.len());

    let kat = VerifyKat {
        scheme: "Falcon-512 / FN-DSA (SHAKE256, DOMAIN_NONE, HASH_ID_RAW)".to_string(),
        logn: 9,
        message_hex: hex(message),
        vrfy_key_hex: hex(&vrfy_key),
        signature_hex: hex(&sig),
    };

    let out_dir = "../packages/falcon/tests/data";
    std::fs::create_dir_all(out_dir).expect("mkdir data");
    let path = format!("{}/verify_kat.json", out_dir);
    std::fs::write(&path, serde_json::to_string_pretty(&kat).unwrap()).expect("write kat");

    eprintln!("[gen-vectors] verify() = {ok}");
    eprintln!("[gen-vectors] vrfy_key = {} bytes, signature = {} bytes", vrfy_key.len(), sig.len());
    eprintln!("[gen-vectors] wrote {path}");
}
