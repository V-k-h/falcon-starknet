.PHONY: test test-rust bench gen-vectors ntt zetas verify-exe verify-exe-looped args

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

# Regenerate the u64 twiddle table for the looped (deployable) NTT.
zetas:
	cargo run -p falcon-codegen --bin cairo-gen -- 512 --zetas packages/falcon/src/ntt_zetas.cairo

# Build the flat, hex-serialized argument file for `scarb execute` from the
# base-Q packed KAT (4 arrays of 29 felts -> [len,elems] x4 = 120 felts).
args:
	python3 -c "import json; d=json.load(open('packages/falcon/tests/data/verify512_packed_args.json')); f=[]; [ (f.append(len(a)), f.extend(a)) for a in d ]; json.dump([hex(x) for x in f], open('packages/verifier_exe/args_looped.json','w'))"
	cp packages/verifier_exe/args_looped.json packages/verifier_exe/args_unrolled.json

# Full verify on a REAL fn-dsa signature, in Cairo STEPS, via `scarb execute`
# (the modern replacement for `scarb cairo-run`). UNROLLED NTT: fast but not
# deployable (~3.7x over the contract class-size cap).
verify-exe: args
	cd packages/verifier_exe && scarb execute --executable-name verify_unrolled \
		--print-program-output --print-resource-usage --arguments-file args_unrolled.json

# Same, but the DEPLOYABLE looped NTT (fits the cap; this is the on-chain path).
verify-exe-looped: args
	cd packages/verifier_exe && scarb execute --executable-name verify_looped \
		--print-program-output --print-resource-usage --arguments-file args_looped.json
