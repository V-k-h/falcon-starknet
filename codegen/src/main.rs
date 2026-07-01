//! cairo-gen — emit the unrolled Cairo NTT.
//!
//! Usage:  cairo-gen <n> [out_path]
//!   n         transform size (power of two, 2n | q-1)
//!   out_path  optional; defaults to stdout

use falcon_codegen::emit::emit_felt252;
use falcon_codegen::ntt::build_ntt_circuit;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    assert!(n.is_power_of_two() && n >= 2, "n must be a power of two >= 2");

    let c = build_ntt_circuit(n);
    let bits = 128 - (c.max_abs_bound().leading_zeros() as i32 - 1).max(0);
    eprintln!(
        "[cairo-gen] n={} ops={} inputs={} outputs={} max_bound~2^{}",
        n,
        c.ops.len(),
        c.inputs.len(),
        c.outputs.len(),
        bits
    );
    let code = emit_felt252(&c, &format!("ntt_{}_inner", n));

    match args.get(2) {
        Some(path) => {
            std::fs::write(path, code).expect("write");
            eprintln!("[cairo-gen] wrote {}", path);
        }
        None => print!("{}", code),
    }
}
