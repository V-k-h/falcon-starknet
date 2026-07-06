//! Uniform (snforge) cost comparison of Falcon-512 hash-to-point backends.
use h2p_bench::{h2p_blake2_run, h2p_keccak_builtin_run, h2p_poseidon_run, h2p_shake_run};

#[test]
fn h2p_poseidon_builtin() {
    assert!(h2p_poseidon_run() != 0, "poseidon");
}
// snforge 0.48.1's VM mishandles the blake2s builtin ("memory cell 3:6");
// measured instead via `scarb cairo-run --function h2p_blake2_run` = 37,567 steps.
#[ignore]
#[test]
fn h2p_blake2_builtin() {
    assert!(h2p_blake2_run() != 0, "blake2");
}
#[test]
fn h2p_keccak_builtin() {
    assert!(h2p_keccak_builtin_run() != 0, "keccak");
}
#[test]
fn h2p_shake_purecairo() {
    assert!(h2p_shake_run() != 0, "shake");
}
