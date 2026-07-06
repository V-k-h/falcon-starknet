//! Looped (deployable) negacyclic NTT-512.
//!
//! The unrolled `ntt_512` is ~10x cheaper per transform in raw VM gas, but its
//! ~300K-felt body is ~3.7x over Starknet's contract class-size cap, so it can
//! never be declared on-chain. This version keeps the SAME transform (identical
//! twiddle table + Cooley-Tukey structure as `ntt_fast_ref`, so existing
//! vectors verify unchanged) but expresses it as a compact loop that fits the
//! cap — while staying cheap in gas via three choices:
//!
//!   1. Work in `Array<u64>` end-to-end: convert felt252->u64 once at load and
//!      u64->felt252 once at output, so butterflies never pay a field-conversion.
//!   2. Nested block/j loops (not a flat index loop), so there is no per-element
//!      division to find the block / twiddle index — only additions.
//!   3. Additive-growth lazy reduction: reduce only the product t = (zeta*x) % q
//!      per butterfly; let top = x+t and bottom = x+q-t ACCUMULATE unreduced.
//!      Each layer grows the bound by at most +q, so after 9 layers values are
//!      < 10q < 2^17 — never overflow u64, always non-negative — and a single
//!      final `% q` canonicalises. This trades 9 full reduction passes for one.
//!
//! Layout note: Cairo arrays are append-only, so each layer READS the previous
//! layer's `Span<u64>` and appends the next layer in index order. Within a block
//! [start, start+2len) the tops occupy [start, start+len) and the bottoms
//! [start+len, start+2len), and blocks are visited in increasing `start`, so
//! appending each block's tops then bottoms yields exact index order.
use crate::ntt_zetas::zetas_512;

const Q: u64 = 12289;

/// Negacyclic NTT of size 512, looped. Span<felt252> in [0,q) → Array<felt252>
/// in bit-reversed order — bit-for-bit equal to the unrolled `ntt_512`.
pub fn ntt_512_looped(input: Span<felt252>) -> Array<felt252> {
    let zs = zetas_512();
    let z = zs.span();

    // Load once into u64, canonicalised into [0, q).
    let mut data: Array<u64> = array![];
    let mut c: u32 = 0;
    while c != 512 {
        let u: u128 = (*input.at(c)).try_into().unwrap();
        let v: u64 = u.try_into().unwrap();
        data.append(v % Q);
        c += 1;
    }

    let mut len: u32 = 256; // halves each layer: 256,128,...,1  (9 layers)
    let mut layer: u32 = 0;
    while layer != 9 {
        let sp = data.span();
        let two_len = len * 2;
        let mut out: Array<u64> = array![];
        let mut k: u32 = 512 / two_len; // z-index of this layer's first block
        let mut start: u32 = 0;
        while start != 512 {
            let zeta = *z.at(k);
            // Single pass: compute t = (zeta*x) % q ONCE per butterfly, append the
            // top now (index order) and stash the bottom; flush bottoms after.
            let mut bottoms: Array<u64> = array![];
            let mut j: u32 = 0;
            while j != len {
                let lo = *sp.at(start + j);
                let t = (zeta * *sp.at(start + len + j)) % Q;
                out.append(lo + t); // top -> [start, start+len)
                bottoms.append(lo + Q - t); // bottom -> [start+len, start+2len)
                j += 1;
            }
            let bsp = bottoms.span();
            let mut m: u32 = 0;
            while m != len {
                out.append(*bsp.at(m));
                m += 1;
            }
            k += 1;
            start += two_len;
        }
        data = out;
        len = len / 2;
        layer += 1;
    }

    // Single final canonicalisation to [0, q), emitted as felt252.
    let sp = data.span();
    let mut result: Array<felt252> = array![];
    let mut i: u32 = 0;
    while i != 512 {
        result.append(((*sp.at(i)) % Q).into());
        i += 1;
    }
    result
}
