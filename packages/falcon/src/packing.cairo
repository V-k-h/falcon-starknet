//! Base-Q coefficient packing: 512 Z_q coefficients <-> felt252 slots, 18 per
//! felt (Horner, base q = 12289), 29 felts total (28 x 18 + 1 x 8). This is the
//! ~17.66x calldata/storage compression. Unpacking enforces canonicality: each
//! extracted digit is < q by construction and the leftover quotient must be zero.

const Q: u256 = 12289;

/// Unpack 512 coefficients (as felt252 in [0,q)) from 29 base-Q-packed felts.
/// Rejects a non-canonical encoding.
pub fn unpack_512(felts: Span<felt252>) -> Array<felt252> {
    let mut out: Array<felt252> = array![];
    let mut fi: u32 = 0;
    while fi != felts.len() {
        let mut x: u256 = (*felts.at(fi)).into();
        let remaining = 512 - out.len();
        let take = if remaining < 18 {
            remaining
        } else {
            18
        };
        let mut j: u32 = 0;
        while j != take {
            let digit: u128 = (x % Q).try_into().unwrap();
            x = x / Q;
            out.append(digit.into());
            j += 1;
        }
        assert!(x == 0, "non-canonical packing");
        fi += 1;
    }
    out
}
