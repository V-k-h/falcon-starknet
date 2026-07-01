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
