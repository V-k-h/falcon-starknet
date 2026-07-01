//! BoundedInt circuit DSL — the Rust replacement for s2morrow's Python `cairo_gen`.
//!
//! Records a straight-line arithmetic trace with automatic bounds tracking, can
//! replay it on integers (`simulate`, the correctness oracle), and emits
//! fully-unrolled Cairo in `felt252` mode (native field arithmetic, reduce only
//! at outputs). i128 bounds suffice while every intermediate stays < 2^128 — the
//! same invariant that makes felt252 mode safe (see cairo-coding skill).

pub const Q: i128 = 12289;

#[derive(Clone, Copy, PartialEq)]
pub enum OpKind {
    Input,
    Const,
    Add,
    Sub,
    Mul,
    Reduce, // reduce operand mod q → [0, q-1]
}

pub struct Op {
    pub kind: OpKind,
    pub a: usize, // operand index (or const value's slot)
    pub b: usize,
    pub val: i128, // for Const
}

/// A recorded circuit. Values are SSA: each `usize` handle indexes `ops`.
pub struct Circuit {
    pub modulus: i128,
    pub ops: Vec<Op>,
    pub lo: Vec<i128>,
    pub hi: Vec<i128>,
    pub inputs: Vec<usize>,
    pub outputs: Vec<usize>,
}

impl Circuit {
    pub fn new(modulus: i128) -> Self {
        Circuit { modulus, ops: vec![], lo: vec![], hi: vec![], inputs: vec![], outputs: vec![] }
    }

    fn push(&mut self, kind: OpKind, a: usize, b: usize, val: i128, lo: i128, hi: i128) -> usize {
        let id = self.ops.len();
        self.ops.push(Op { kind, a, b, val });
        self.lo.push(lo);
        self.hi.push(hi);
        id
    }

    pub fn input(&mut self, lo: i128, hi: i128) -> usize {
        let id = self.push(OpKind::Input, 0, 0, 0, lo, hi);
        self.inputs.push(id);
        id
    }

    pub fn constant(&mut self, v: i128) -> usize {
        self.push(OpKind::Const, 0, 0, v, v, v)
    }

    pub fn add(&mut self, a: usize, b: usize) -> usize {
        self.push(OpKind::Add, a, b, 0, self.lo[a] + self.lo[b], self.hi[a] + self.hi[b])
    }

    pub fn sub(&mut self, a: usize, b: usize) -> usize {
        // correct subtraction bounds: [a_lo - b_hi, a_hi - b_lo]
        self.push(OpKind::Sub, a, b, 0, self.lo[a] - self.hi[b], self.hi[a] - self.lo[b])
    }

    pub fn mul(&mut self, a: usize, b: usize) -> usize {
        let p = [self.lo[a] * self.lo[b], self.lo[a] * self.hi[b], self.hi[a] * self.lo[b], self.hi[a] * self.hi[b]];
        let lo = *p.iter().min().unwrap();
        let hi = *p.iter().max().unwrap();
        self.push(OpKind::Mul, a, b, 0, lo, hi)
    }

    /// Reduce mod q. Operand must be non-negative and < 2^128 (caller keeps it so
    /// via the SHIFT pattern), so felt252→u128→(% q) is faithful. Bounds → [0, q-1].
    pub fn reduce(&mut self, a: usize) -> usize {
        assert!(self.lo[a] >= 0, "reduce operand must be non-negative (add SHIFT first)");
        assert!(self.hi[a] < (1i128 << 120), "reduce operand must be < 2^120 (felt252-safe, i128-safe)");
        self.push(OpKind::Reduce, a, 0, 0, 0, self.modulus - 1)
    }

    pub fn set_output(&mut self, v: usize) {
        self.outputs.push(v);
    }

    /// Largest |bound| across the trace — must stay < 2^128 for felt252 mode.
    pub fn max_abs_bound(&self) -> i128 {
        self.lo.iter().chain(self.hi.iter()).map(|x| x.abs()).max().unwrap_or(0)
    }

    /// Replay the trace on concrete inputs; outputs reduced mod q. The oracle.
    pub fn simulate(&self, inputs: &[i128]) -> Vec<i128> {
        let mut val = vec![0i128; self.ops.len()];
        let mut ii = 0;
        for (id, op) in self.ops.iter().enumerate() {
            val[id] = match op.kind {
                OpKind::Input => {
                    let v = inputs[ii];
                    ii += 1;
                    v
                }
                OpKind::Const => op.val,
                OpKind::Add => val[op.a] + val[op.b],
                OpKind::Sub => val[op.a] - val[op.b],
                OpKind::Mul => val[op.a] * val[op.b],
                OpKind::Reduce => ((val[op.a] % self.modulus) + self.modulus) % self.modulus,
            };
        }
        self.outputs
            .iter()
            .map(|&o| ((val[o] % self.modulus) + self.modulus) % self.modulus)
            .collect()
    }
}
