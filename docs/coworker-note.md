# Falcon-512 verifier — live on Starknet Sepolia

The full standard Falcon-512 (FN-DSA) verify now runs **entirely on-chain** — SHAKE-256
hash-to-point + both NTTs + norm check — and it verifies a **real** fn-dsa signature in a live
transaction. Key hurdle solved: the fully-unrolled NTT is 3.74× over the contract class-size cap, so
I swapped in a compact looped NTT (bit-for-bit identical) that fits and deploys.

**Deployed (Sepolia), all on a real signature:**
- **`assert_verify_from_pk`** — a passing transaction *is* the proof: verifies fully on-chain from
  the raw pubkey and **reverts on an invalid signature**, emitting `Verified` on success. Gate
  contract [`0x07110d6e…056240`](https://sepolia.voyager.online/contract/0x07110d6eaabc20f6713cf0b32dccfaf0ee9d24b0b94034e8ac0871709b056240),
  valid-sig tx [`0x0332bef4…`](https://sepolia.voyager.online/tx/0x0332bef426e248cd4a3030f487dd7a0fc5c611e75a9a02df3ea3ab5ba9786569) — **SUCCEEDED**, `Verified{ok:true}`, 1.07B L2 gas. (Tampered sig → `false` → tx would revert.)
- `verify_from_pk` — same verify, returns bool: tx [`0x055614c8…`](https://sepolia.voyager.online/tx/0x055614c84bce1a3b70bc3ef7f83ad193d80862a0e3ca8d40940f44bcb624d0d4).
- `verify_full` — hash-to-point on-chain, pre-decoded pubkey: **705M gas**, tx [`0x027162a7…`](https://sepolia.voyager.online/tx/0x027162a7633e609bc0b539c24dcf4858918e928b01e01fb4204c211b781b409d).

Repo: `github.com/V-k-h/falcon-starknet` (`docs/implementation.tex` for details). SHAKE dominates
cost; a `keccak_f1600` syscall (SNIP-32) would cut it sharply.
