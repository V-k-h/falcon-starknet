# falcon-starknet

Standard **Falcon-512** (NIST FN-DSA) post-quantum signature **verification** for Starknet, plus a benchmarking harness.

Signing/keygen stay off-chain (they need floating point); only verification runs on-chain, where it's integer-only: NTT mod `q = 12289`, a hash-to-point, and an L2-norm check.

## Design decisions (why)

- **Standard SHAKE256, not Poseidon.** The Poseidon variant (s2morrow) is ~50× cheaper on-chain but non-standard — it can't verify real Falcon signatures. We target interoperability. Hash-to-point is behind a trait so a Poseidon backend can be benchmarked side-by-side.
- **The bottleneck is the hash, not the lattice math.** Starknet has no SHAKE primitive today, so SHAKE256 runs as pure-Cairo Keccak-f[1600] (measured ~360K steps/permutation). [SNIP-32](https://community.starknet.io/t/snip-32-expose-keccak-f-1600-permutation-syscall/115770) would expose a `keccak_f1600` syscall and collapse this to ~Poseidon cost; the permutation is isolated so the swap is one function.
- **Hint-based verification (2 NTTs, 0 INTTs).** The signer supplies `mul_hint`; the chain checks it with forward NTTs only.
- **Codegen in Rust, not Python.** A circuit DSL (`codegen/`) traces the NTT and emits fully-unrolled Cairo (`felt252` mode — native arithmetic, reduce only at outputs; safe because Falcon's `q` keeps all intermediates < 2¹²⁸).
- **`rust-fn-dsa` as the reference.** Thomas Pornin's public-domain FN-DSA crate is the authoritative signer / KAT oracle (`reference/`).

## Layout

```
packages/falcon/   Cairo verifier   (zq ✓, shake256 ✓ KAT-verified, ntt/hash_to_point/packing/verify → todo)
codegen/           Rust NTT circuit DSL → emits unrolled Cairo   (seed ✓)
reference/         Rust FN-DSA reference + KAT generator   (stub)
benches/           per-component steps/gas harness   (todo)
```

## Build order (each layer proven before the next)

| # | Milestone | Status |
|---|-----------|--------|
| M0 | Scaffold + toolchain + tests green | ✅ |
| M1 | `zq` mod-12289 arithmetic (→ BoundedInt) | seed ✅ |
| M2 | Unrolled NTT via `codegen`, diff-tested vs reference | ✅ fast O(n·log n) NTT: convolution-correct + felt252-safe to n=512 (Rust); Cairo diff-test at n=128. n=512 emits/compiles but trips snforge's Sierra-cost path — reduce-frequency optimization pending (M2-opt) |
| M3 | SHAKE256 ✅ + hash-to-point (rejection sampling) | ✅ KAT-verified; measured 3.73M steps / ~534M gas |
| M4 | hint-based `verify()` core + norm bound | ✅ core (hint-check + norm) validated end-to-end at n=4 (accept + 2 reject paths). Real fn-dsa sig/pubkey byte decoding + FN-DSA hash framing = M4-decode (next); n=512 gated on M2-opt |
| M5 | benchmark harness (SHAKE vs Poseidon backends) | todo |

## Run

```bash
# Cairo verifier
cd packages/falcon && snforge test

# Rust reference + codegen
cargo test

# regenerate an unrolled NTT (seed: direct O(n^2) transform)
cargo run -p falcon-codegen --bin cairo-gen -- 8 packages/falcon/src/ntt_felt252.cairo
```

## Status

M0/M1 green. `packages/falcon` has KAT-verified SHAKE256 and seed `zq`. The `codegen` pipeline (DSL → simulate oracle → emit compiling Cairo) works end-to-end on a seed NTT. Next: real Falcon-convention unrolled NTT-512 in `codegen`, validated against `rust-fn-dsa` vectors (M2), then hash-to-point (M3).
