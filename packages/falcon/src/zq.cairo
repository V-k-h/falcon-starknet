//! Zq — arithmetic modulo q = 12289, the Falcon-512 ring modulus.
//!
//! SEED IMPLEMENTATION (M1): correct but unoptimized, using u16/u32 intermediates.
//! TODO (M1-opt): migrate `Zq` to `BoundedInt<0, 12288>` with lazy reduction via
//! `bounded_int_div_rem`, per the cairo-coding skill. Keep this public interface
//! (`add_mod`/`sub_mod`/`mul_mod`) stable so the swap is localized.

/// Falcon-512 ring modulus.
pub const Q: u16 = 12289;

/// A residue in [0, q). Seed alias; becomes BoundedInt<0, 12288> later.
pub type Zq = u16;

/// (a + b) mod q
pub fn add_mod(a: Zq, b: Zq) -> Zq {
    let s: u32 = a.into() + b.into();
    (s % 12289).try_into().unwrap()
}

/// (a - b) mod q  (no underflow: add q before subtracting)
pub fn sub_mod(a: Zq, b: Zq) -> Zq {
    let aa: u32 = a.into();
    let bb: u32 = b.into();
    ((aa + 12289 - bb) % 12289).try_into().unwrap()
}

/// (a * b) mod q   (product < 12289^2 ≈ 1.5e8, fits u32)
pub fn mul_mod(a: Zq, b: Zq) -> Zq {
    let p: u32 = a.into() * b.into();
    (p % 12289).try_into().unwrap()
}
