# falcon-starknet

Standard **Falcon-512** (NIST FN-DSA) post-quantum signature **verification** for Starknet, plus a benchmarking harness.

Signing/keygen stay off-chain (they need floating point); only verification runs on-chain, where it's integer-only: NTT mod `q = 12289`, a hash-to-point, and an L2-norm check.

## Live on Starknet Sepolia

A **fully self-contained, interoperable standard Falcon-512 verifier** is deployed and **verified a real fn-dsa signature on-chain, in a real transaction** — hashing the message with SHAKE-256 and running the NTTs + norm check entirely on Starknet.

| | value |
|---|---|
| Contract (self-contained) | [`0x022a50446b59492b08eb740dd38a5f2446676e85932af8c784c94f1b282d1c24`](https://sepolia.voyager.online/contract/0x022a50446b59492b08eb740dd38a5f2446676e85932af8c784c94f1b282d1c24) |
| Class hash | [`0x593379f8ef06dacefc71309020b459a97a960b901f3eac6ddf64ac786a6468f`](https://sepolia.voyager.online/class/0x0593379f8ef06dacefc71309020b459a97a960b901f3eac6ddf64ac786a6468f) |
| `verify_full(framed, s2, pk_ntt, mul_hint) -> true` — invoke tx | [`0x027162a7...b781b409d`](https://sepolia.voyager.online/tx/0x027162a7633e609bc0b539c24dcf4858918e928b01e01fb4204c211b781b409d) |
| Cost of that tx | **704,797,440 L2 gas** (~20 testnet STRK) — SHAKE hash-to-point dominates |
| `verify(...)` — hint/norm core, pre-hashed msg_point | also embedded (looped NTT) |

`verify_full` computes `msg_point = HashToPoint(nonce ‖ SHAKE256(pk)[0..64] ‖ 0x00 ‖ 0x00 ‖ message)` on-chain with interoperable SHAKE-256 — so it verifies *real* Falcon signatures, no trusted pre-hash. Cost is dominated by the pure-Cairo SHAKE (~3.7M of the ~4.7M steps); a `keccak_f1600` syscall (SNIP-32) would cut it sharply.

**No trust at all in the hash inputs:** `verify_from_pk(vrfy_key, nonce, message, s2, pk_ntt, mul_hint)` additionally computes `hpk = SHAKE256(vrfy_key)[0..64]` on-chain from the raw encoded public key, so *nothing* hash-related is precomputed off-chain. Proven end-to-end (`scarb execute` → accepts, **7,579,101 steps**) and fits the class-size cap. Its live Sepolia declare is pending a testnet-STRK top-up (the larger class costs more to declare).

The NTT uses `ntt_512_looped` (compact looped transform). The fully-unrolled NTT is ~10× cheaper per transform but its ~306k-felt class is ~3.7× over Starknet's contract class-size cap, so it cannot be declared. See [docs/implementation.tex](docs/implementation.tex) §Deployability.

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
| M2 | Unrolled NTT via `codegen`, diff-tested vs reference | ✅ fast O(n·log n) NTT with lazy reduction; **n=512 compiles & passes snforge** (57K steps / ~17.2M gas), diff-tested vs Rust reference |
| M3 | SHAKE256 ✅ + hash-to-point (rejection sampling) | ✅ KAT-verified; measured 3.73M steps / ~534M gas |
| M4 | full verify + real-signature e2e | ✅ FN-DSA hash framing pinned (nonce‖SHAKE256(pk)[64]‖0x00‖0x00‖msg); pubkey+sig decoders round-trip-validated; **real fn-dsa Falcon-512 signature verified in Cairo** (verify_core: hint-check + norm, 198K steps). Full in-`verify` double-NTT gated on a CASM frame-offset opt (NTTs precomputed; Cairo ntt_512 proven separately in test_ntt512) |
| M5 | benchmark harness | ✅ `make bench` → per-component steps/gas table (benches/bench.sh, benches/RESULTS.md) |

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

## Full in-`verify` NTT — resolved

`verify_hint_512` runs BOTH forward NTTs itself; snforge's universal-sierra-compiler hit offset/statement limits on that, so it runs via `scarb cairo-run` (a different compiler path) in the `verifier_exe` package. `make verify-exe` executes it on a real fn-dsa Falcon-512 signature and returns `[1]` (accepted) at ~143K steps.
