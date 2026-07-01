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

// ---------------------------------------------------------------------------
// Fast NTT (M2): complete negacyclic Cooley-Tukey, O(n log n).
//
// zetas[i] = psi^{bitrev(i)}; standard DIT butterflies. Output is in
// bit-reversed order — fine, because verification only needs the convolution
// property (NTT(a)∘NTT(b) = NTT(a·b)), which holds elementwise in any fixed
// order, as long as ALL operands use this same transform.
// ---------------------------------------------------------------------------

/// Smallest multiple of q that is ≥ (q-1)^2 = 150994944.  (12288·12289)
pub const SHIFT: i128 = 151007232;

fn bitrev(mut i: usize, bits: u32) -> usize {
    let mut r = 0usize;
    for _ in 0..bits {
        r = (r << 1) | (i & 1);
        i >>= 1;
    }
    r
}

fn zetas(n: usize) -> Vec<i128> {
    let logn = n.trailing_zeros();
    let psi = psi_2n(n as i128);
    (0..n).map(|i| powmod(psi, bitrev(i, logn) as i128, Q)).collect()
}

/// Integer reference for the fast negacyclic NTT (in-place CT, bit-reversed out).
pub fn ntt_fast_ref(a: &[i128]) -> Vec<i128> {
    let n = a.len();
    let z = zetas(n);
    let mut x: Vec<i128> = a.iter().map(|&v| ((v % Q) + Q) % Q).collect();
    let mut k = 1usize;
    let mut len = n / 2;
    while len >= 1 {
        let mut start = 0;
        while start < n {
            let zeta = z[k];
            k += 1;
            for j in start..start + len {
                let t = zeta * x[j + len] % Q;
                x[j + len] = ((x[j] - t) % Q + Q) % Q;
                x[j] = (x[j] + t) % Q;
            }
            start += 2 * len;
        }
        len /= 2;
    }
    x
}

/// How many butterfly layers between reductions. Bounds grow ~q per layer, so
/// after k layers the magnitude is ~q^(k+1); k=6 → ~q^7 ≈ 2^95, safely < 2^120
/// (i128/tracker) and < 2^128 (felt→u128 at reduction). Fewer reductions ⇒ far
/// less generated code (this is the M2-opt that lets n=512 compile).
pub const REDUCE_EVERY: usize = 6;

/// Trace the fast NTT into a circuit with LAZY reduction (reduce every
/// REDUCE_EVERY layers + at the end). All field values stay non-negative via a
/// per-butterfly SHIFT (a multiple of q ≥ the subtrahend's bound), so the emitted
/// felt252 arithmetic is faithful and reduction is a plain u128 `% q`.
pub fn build_ntt_fast_circuit(n: usize) -> Circuit {
    let z = zetas(n);
    let mut c = Circuit::new(Q);
    let mut x: Vec<usize> = (0..n).map(|_| c.input(0, Q - 1)).collect();

    let mut k = 1usize;
    let mut len = n / 2;
    let mut layer = 0usize;
    while len >= 1 {
        while_layer(&mut c, &z, &mut k, &mut x, len, n);
        layer += 1;
        len /= 2;
        if layer % REDUCE_EVERY == 0 {
            for i in 0..n {
                x[i] = c.reduce(x[i]);
            }
        }
    }
    if layer % REDUCE_EVERY != 0 {
        for i in 0..n {
            x[i] = c.reduce(x[i]);
        }
    }
    for &v in &x {
        c.set_output(v);
    }
    c
}

/// One CT layer of butterflies (no reduction; SHIFT keeps values non-negative).
fn while_layer(c: &mut Circuit, z: &[i128], k: &mut usize, x: &mut [usize], len: usize, n: usize) {
    let mut start = 0;
    while start < n {
        let zeta = c.constant(z[*k]);
        *k += 1;
        for j in start..start + len {
            let t = c.mul(x[j + len], zeta);
            // SHIFT = smallest multiple of q ≥ current bound of t, so lo ≥ 0.
            let t_hi = c.hi[t];
            let shift_val = ((t_hi + Q - 1) / Q) * Q;
            let shift = c.constant(shift_val);
            let hi = c.add(x[j], t);
            let a_sh = c.add(x[j], shift);
            let lo = c.sub(a_sh, t);
            x[j] = hi;
            x[j + len] = lo;
        }
        start += 2 * len;
    }
}
