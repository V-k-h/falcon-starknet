//! NTT circuit generation (SEED).
//!
//! This traces a *direct* O(n^2) negacyclic NTT into the DSL — deliberately
//! simple and obviously correct, to prove the codegen pipeline end-to-end
//! (trace → simulate oracle → emit Cairo).
//!
//! TODO (M2): replace with the fast recursive/CT unrolled transform AND align
//! the root convention to Falcon's, validated by differential test against the
//! Rust reference (`rust-fn-dsa`) vectors — the s2morrow-style unrolled NTT.

use crate::circuit::{Circuit, Q};

fn powmod(mut base: i128, mut exp: i128, m: i128) -> i128 {
    let mut r = 1i128;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            r = r * base % m;
        }
        base = base * base % m;
        exp >>= 1;
    }
    r
}

/// A primitive 2n-th root of unity mod q (psi), so psi^(2n)=1, psi^n=-1.
/// q-1 = 12288 = 2^12 * 3, so any power of two up to 2^12 divides it.
pub fn psi_2n(n: i128) -> i128 {
    let order = 2 * n;
    assert!((Q - 1) % order == 0, "2n must divide q-1");
    // g = 11 is a primitive root mod 12289; psi = g^((q-1)/2n).
    let g = 11i128;
    powmod(g, (Q - 1) / order, Q)
}

/// Integer reference: negacyclic NTT, â_j = Σ_i a_i · psi^{(2j+1)i} mod q.
pub fn ntt_direct_ref(a: &[i128]) -> Vec<i128> {
    let n = a.len() as i128;
    let psi = psi_2n(n);
    let mut out = vec![0i128; a.len()];
    for j in 0..a.len() {
        let mut acc = 0i128;
        for i in 0..a.len() {
            let e = ((2 * j as i128 + 1) * i as i128) % (2 * n);
            acc = (acc + a[i] * powmod(psi, e, Q)) % Q;
        }
        out[j] = acc;
    }
    out
}

/// Trace the same direct negacyclic NTT into a circuit (unrolled, straight-line).
pub fn build_ntt_circuit(n: usize) -> Circuit {
    let nn = n as i128;
    let psi = psi_2n(nn);
    let mut c = Circuit::new(Q);
    let inputs: Vec<usize> = (0..n).map(|_| c.input(0, Q - 1)).collect();

    for j in 0..n {
        // acc = Σ_i input_i * const(psi^{(2j+1)i})
        let mut acc: Option<usize> = None;
        for i in 0..n {
            let e = ((2 * j as i128 + 1) * i as i128) % (2 * nn);
            let tw = c.constant(powmod(psi, e, Q));
            let term = c.mul(inputs[i], tw);
            acc = Some(match acc {
                None => term,
                Some(prev) => c.add(prev, term),
            });
        }
        c.set_output(acc.unwrap());
    }
    c
}
