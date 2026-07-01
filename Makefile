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

# Regenerate the unrolled NTT (n=512) from the codegen
ntt:
	cargo run -p falcon-codegen --bin cairo-gen -- 512 packages/falcon/src/ntt512.cairo
