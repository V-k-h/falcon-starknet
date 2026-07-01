# Falcon-512 Cairo verifier — benchmarks

Measured with `snforge test --detailed-resources` (scarb 2.12.1). Hash-to-point
uses **standard SHAKE256** (pure-Cairo Keccak-f[1600]); the NTT is the codegen'd
n=512 unrolled transform; verify is the hint-based core.

| Component | Steps | L2 gas |
|---|--:|--:|
| verify_accepts_valid | 1138 | 360000 |
| zq_sub_underflow | 59 | 40000 |
| verify_rejects_tampered_hint | 401 | 120000 |
| zq_mul_reduces | 59 | 40000 |
| ntt_128_matches_reference | 13869 | 4320000 |
| ntt_512_matches_reference | 57005 | 17240000 |
| zq_add_wraps | 59 | 40000 |
| verify_rejects_large_norm | 1147 | 360000 |
| shake_empty | 375917 | 51600000 |
| shake_abc | 375947 | 51600000 |
| verify_real_falcon512_signature | 198347 | 44280000 |
| shake_abc_multiblock_squeeze | 735923 | 101200000 |
| hash_to_point_kat | 3727918 | 534640000 |

_Note: hash_to_point dominates — standard SHAKE256 in pure Cairo is ~3.7M steps
(~10 Keccak-f[1600] permutations). SNIP-32 (keccak_f1600 syscall) would collapse this._
