.PHONY: test test-rust bench gen-vectors ntt

# Cairo verifier tests
test:
	cd packages/falcon && snforge test

# Rust reference + codegen tests
test-rust:
	cargo test

# Per-component steps/gas benchmark table
bench:
	./benches/bench.sh

# Regenerate KAT vectors from the fn-dsa reference
gen-vectors:
	cd reference && cargo run --bin gen-vectors

# Regenerate the unrolled NTT (n=512) from the codegen. The default (tuple) emit
# is ~12% cheaper in gas (6.51M vs 7.29M L2). Add `--layered` to emit one function
# per NTT layer (threaded via Array<felt252>) for smaller per-frame offsets; note
# this does NOT make the verifier deployable — the unrolled ntt_512 is ~3.7x over
# Starknet's contract class-size cap regardless (see packages/verifier_contract).
ntt:
	cargo run -p falcon-codegen --bin cairo-gen -- 512 packages/falcon/src/ntt512.cairo

# Full verify (both NTTs in-line) on the real fn-dsa signature via cairo-run
verify-exe:
	cd packages/verifier_exe && scarb cairo-run --print-resource-usage "$$(cat ../falcon/tests/data/verify512_args.json)"
