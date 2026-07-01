//! falcon-reference — authoritative Falcon-512 reference + KAT vector generator.
//!
//! SEED: placeholder. The plan (M1/M4) is to build on Thomas Pornin's public-domain
//! `rust-fn-dsa` (standard SHAKE256) and emit JSON test vectors consumed by the
//! Cairo tests: mod-q arithmetic, NTT, hash-to-point, and end-to-end verify.

pub mod falcon_codec;

/// Falcon-512 parameters.
pub const N: usize = 512;
pub const Q: u32 = 12289;
/// Squared L2 acceptance bound for Falcon-512 (l2bound[9]).
pub const SIG_BOUND: u64 = 34_034_726;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn params() {
        assert_eq!(N, 512);
        assert_eq!(Q, 12289);
        assert_eq!(SIG_BOUND, 34_034_726);
    }
}
