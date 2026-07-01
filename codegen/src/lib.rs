//! falcon-codegen — Rust circuit DSL that emits unrolled Cairo NTT for Falcon-512.
//! Replaces s2morrow's Python `cairo_gen`. See ntt.rs for the current seed scope.

pub mod circuit;
pub mod emit;
pub mod ntt;

#[cfg(test)]
mod tests {
    use crate::circuit::Q;
    use crate::ntt::{build_ntt_circuit, ntt_direct_ref, psi_2n};

    fn powmod(mut b: i128, mut e: i128, m: i128) -> i128 {
        let mut r = 1;
        b %= m;
        while e > 0 {
            if e & 1 == 1 {
                r = r * b % m;
            }
            b = b * b % m;
            e >>= 1;
        }
        r
    }

    /// Negacyclic convolution a*b mod (x^n + 1), mod q.
    fn negacyclic_conv(a: &[i128], b: &[i128]) -> Vec<i128> {
        let n = a.len();
        let mut c = vec![0i128; n];
        for i in 0..n {
            for j in 0..n {
                let k = i + j;
                if k < n {
                    c[k] = (c[k] + a[i] * b[j]) % Q;
                } else {
                    c[k - n] = (c[k - n] - a[i] * b[j] % Q + Q) % Q;
                }
            }
        }
        c
    }

    #[test]
    fn psi_is_2n_root() {
        for &n in &[2i128, 4, 8, 16, 512] {
            let psi = psi_2n(n);
            assert_eq!(powmod(psi, 2 * n, Q), 1, "psi^2n == 1");
            assert_eq!(powmod(psi, n, Q), Q - 1, "psi^n == -1 (negacyclic)");
        }
    }

    #[test]
    fn ntt_ref_is_negacyclic() {
        // NTT(a) ∘ NTT(b) == NTT(a *neg b) pointwise — proves it's a real transform.
        let a = vec![1i128, 2, 3, 4, 5, 6, 7, 8];
        let b = vec![8i128, 7, 6, 5, 4, 3, 2, 1];
        let na = ntt_direct_ref(&a);
        let nb = ntt_direct_ref(&b);
        let nc = ntt_direct_ref(&negacyclic_conv(&a, &b));
        for j in 0..a.len() {
            assert_eq!((na[j] * nb[j]) % Q, nc[j], "convolution property at {}", j);
        }
    }

    #[test]
    fn circuit_matches_reference() {
        // The emitted circuit's simulate() must equal the integer reference — pipeline fidelity.
        for &n in &[4usize, 8, 16] {
            let c = build_ntt_circuit(n);
            assert!(c.max_abs_bound() < (1i128 << 120), "bounds felt252-safe");
            let input: Vec<i128> = (0..n as i128).map(|i| (i * 37 + 5) % Q).collect();
            assert_eq!(c.simulate(&input), ntt_direct_ref(&input), "n={}", n);
        }
    }

    // ---- M2: fast NTT ----
    use crate::ntt::{build_ntt_fast_circuit, ntt_fast_ref};

    #[test]
    fn fast_ntt_is_negacyclic() {
        // Convolution property proves the fast transform is a correct negacyclic NTT.
        for &n in &[4usize, 8, 16, 32] {
            let a: Vec<i128> = (0..n as i128).map(|i| (i * 31 + 1) % Q).collect();
            let b: Vec<i128> = (0..n as i128).map(|i| (i * 17 + 9) % Q).collect();
            let na = ntt_fast_ref(&a);
            let nb = ntt_fast_ref(&b);
            let nc = ntt_fast_ref(&negacyclic_conv(&a, &b));
            for i in 0..n {
                assert_eq!((na[i] * nb[i]) % Q, nc[i], "conv n={} i={}", n, i);
            }
        }
    }

    #[test]
    fn fast_circuit_matches_ref_and_is_felt252_safe() {
        for &n in &[4usize, 8, 16, 32, 64, 128, 256, 512] {
            let c = build_ntt_fast_circuit(n);
            assert!(c.max_abs_bound() < (1i128 << 120), "n={} bounds must be felt252-safe", n);
            let input: Vec<i128> = (0..n as i128).map(|i| (i * 41 + 7) % Q).collect();
            assert_eq!(c.simulate(&input), ntt_fast_ref(&input), "fidelity n={}", n);
        }
    }

    #[test]
    fn fast_ntt_512_op_count_is_nlogn() {
        // sanity: O(n log n), far below the direct O(n^2)
        let c = build_ntt_fast_circuit(512);
        assert!(c.ops.len() < 40_000, "n=512 ops = {} (should be ~n log n)", c.ops.len());
    }
}

#[cfg(test)]
mod vectors {
    use crate::ntt::ntt_fast_ref;
    use crate::circuit::Q;
    #[test]
    fn print_ntt_vector() {
        let input: Vec<i128> = (0..128i128).map(|i| (i * 41 + 7) % Q).collect();
        let out = ntt_fast_ref(&input);
        let sum: i128 = out.iter().sum();
        println!("NTT128_SUM={}", sum);
        println!("NTT128_0={}", out[0]);
        println!("NTT128_1={}", out[1]);
        println!("NTT128_63={}", out[63]);
        println!("NTT128_127={}", out[127]);
    }
}
