//! cairo-gen — emit the unrolled Cairo NTT.
//!
//! Usage:  cairo-gen <n> [out_path]
//!   n         transform size (power of two, 2n | q-1)
//!   out_path  optional; defaults to stdout

use falcon_codegen::emit::{emit_module, emit_module_layered, emit_zetas_table};
use falcon_codegen::ntt::{build_ntt_fast_circuit, build_ntt_fast_circuit_layered};

fn main() {
    let raw: Vec<String> = std::env::args().collect();
    let layered = raw.iter().any(|a| a == "--layered");
    let zetas = raw.iter().any(|a| a == "--zetas");
    let args: Vec<String> =
        raw.into_iter().filter(|a| a != "--layered" && a != "--zetas").collect();
    let n: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8);
    assert!(n.is_power_of_two() && n >= 2, "n must be a power of two >= 2");

    // --zetas: emit only the twiddle table for the hand-written looped NTT.
    if zetas {
        let code = emit_zetas_table(n);
        eprintln!("[cairo-gen] n={} zetas-table ({} entries)", n, n);
        match args.get(2) {
            Some(path) => {
                std::fs::write(path, code).expect("write");
                eprintln!("[cairo-gen] wrote {}", path);
            }
            None => print!("{}", code),
        }
        return;
    }

    let (c, code) = if layered {
        let (c, snaps) = build_ntt_fast_circuit_layered(n);
        let code = emit_module_layered(&c, &snaps, n);
        (c, code)
    } else {
        let c = build_ntt_fast_circuit(n);
        let code = emit_module(&c, n);
        (c, code)
    };
    let bits = 128 - (c.max_abs_bound().leading_zeros() as i32 - 1).max(0);
    eprintln!(
        "[cairo-gen] n={} layered={} ops={} inputs={} outputs={} max_bound~2^{}",
        n,
        layered,
        c.ops.len(),
        c.inputs.len(),
        c.outputs.len(),
        bits
    );

    match args.get(2) {
        Some(path) => {
            std::fs::write(path, code).expect("write");
            eprintln!("[cairo-gen] wrote {}", path);
        }
        None => print!("{}", code),
    }
}
