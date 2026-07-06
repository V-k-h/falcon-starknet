//! Base-Q coefficient packing: 512 Z_q coefficients <-> felt252 slots, 18 per
//! felt, 29 felts total. This is the ~17.66x calldata/storage compression.
//!
//! Layout (s2morrow-compatible): each felt holds two u128 halves,
//!   felt = lo + hi * 2^128,  lo = sum_{j<9} v_j q^j,  hi = sum_{j<9} v_{9+j} q^j,
//! since q^9 ~ 2^122 < 2^128. Unpacking uses u128 divmods (cheaper than u256).
//! Canonicality is enforced: each digit is < q and each half's leftover is zero.

const Q: u128 = 12289;

/// Unpack 512 coefficients (as felt252 in [0,q)) from 29 packed felts.
/// Rejects a non-canonical encoding.
pub fn unpack_512(felts: Span<felt252>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut fi: u32 = 0;
    while fi != felts.len() {
        let x: u256 = (*felts.at(fi)).into();
        let remaining = 512 - out.len();
        let take = if remaining < 18 {
            remaining
        } else {
            18
        };
        let take_lo = if take < 9 {
            take
        } else {
            9
        };

        // low half (u128 divmods)
        let mut lo = x.low;
        let mut j: u32 = 0;
        while j != take_lo {
            let d = lo % Q;
            lo = lo / Q;
            out.append(d.into());
            j += 1;
        }
        assert!(lo == 0, "non-canonical low half");

        // high half
        let mut hi = x.high;
        let mut k: u32 = 0;
        while k != take - take_lo {
            let d = hi % Q;
            hi = hi / Q;
            out.append(d.into());
            k += 1;
        }
        assert!(hi == 0, "non-canonical high half");

        fi += 1;
    }
    out
}
