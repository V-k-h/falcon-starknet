//! Pure-Cairo SHAKE256 (Keccak-f[1600], 0x1F padding, rate = 136 bytes).
//! Built because the corelib keccak_syscall bakes in 0x01 padding and exposes
//! only 256 output bits — neither works for Falcon's SHAKE256 hash-to-point.

const MASK64_U128: u128 = 0xffffffffffffffff;
const NOTMASK: u64 = 0xffffffffffffffff;

/// 2^n for n in 0..=63, table lookup (no loop)
fn pow2_u128(n: u32) -> u128 {
    let t = array![
        0x1, 0x2, 0x4, 0x8, 0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000, 0x2000,
        0x4000, 0x8000, 0x10000, 0x20000, 0x40000, 0x80000, 0x100000, 0x200000, 0x400000, 0x800000,
        0x1000000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000,
        0x100000000, 0x200000000, 0x400000000, 0x800000000, 0x1000000000, 0x2000000000,
        0x4000000000, 0x8000000000, 0x10000000000, 0x20000000000, 0x40000000000, 0x80000000000,
        0x100000000000, 0x200000000000, 0x400000000000, 0x800000000000, 0x1000000000000,
        0x2000000000000, 0x4000000000000, 0x8000000000000, 0x10000000000000, 0x20000000000000,
        0x40000000000000, 0x80000000000000, 0x100000000000000, 0x200000000000000,
        0x400000000000000, 0x800000000000000, 0x1000000000000000, 0x2000000000000000,
        0x4000000000000000, 0x8000000000000000,
    ];
    *t.at(n)
}

fn pi_src() -> Span<u32> {
    array![
        0, 6, 12, 18, 24, 3, 9, 10, 16, 22, 1, 7, 13, 19, 20, 4, 5, 11, 17, 23, 2, 8, 14, 15, 21,
    ]
        .span()
}

fn pi_rho() -> Span<u32> {
    array![
        0, 44, 43, 21, 14, 28, 20, 3, 45, 61, 1, 6, 25, 8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41,
        2,
    ]
        .span()
}

/// rotate-left of a 64-bit lane by n (0..63)
fn rotl(x: u64, n: u32) -> u64 {
    if n == 0 {
        return x;
    }
    let xu: u128 = x.into();
    let prod: u128 = xu * pow2_u128(n);
    let lo: u128 = prod & MASK64_U128;
    let hi: u128 = prod / 0x10000000000000000;
    let res: u128 = lo | hi;
    res.try_into().unwrap()
}

fn round_constants() -> Span<u64> {
    array![
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
        .span()
}

fn rho_offsets() -> Span<u32> {
    array![
        0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56,
        14,
    ]
        .span()
}

/// one Keccak-f round
fn keccak_round(s: Span<u64>, rc: u64) -> Array<u64> {
    // theta: column parities
    let mut c = array![];
    let mut x: u32 = 0;
    while x != 5 {
        let v = *s.at(x) ^ *s.at(x + 5) ^ *s.at(x + 10) ^ *s.at(x + 15) ^ *s.at(x + 20);
        c.append(v);
        x += 1;
    }
    // a2[x+5y] = s[x+5y] ^ (c[(x+4)%5] ^ rotl(c[(x+1)%5],1))
    let mut a2 = array![];
    let mut idx: u32 = 0;
    while idx != 25 {
        let xx = idx % 5;
        let d = *c.at((xx + 4) % 5) ^ rotl(*c.at((xx + 1) % 5), 1);
        a2.append(*s.at(idx) ^ d);
        idx += 1;
    }
    // rho + pi: b[d] = rotl(a2[PI_SRC[d]], PI_RHO[d]) — table-driven, no dict
    let psrc = pi_src();
    let prho = pi_rho();
    let mut b = array![];
    let mut d: u32 = 0;
    while d != 25 {
        b.append(rotl(*a2.at(*psrc.at(d)), *prho.at(d)));
        d += 1;
    }
    // chi + iota
    let mut out = array![];
    let mut yy: u32 = 0;
    while yy != 5 {
        let row = 5 * yy;
        let b0r = *b.at(row);
        let b1r = *b.at(row + 1);
        let b2r = *b.at(row + 2);
        let b3r = *b.at(row + 3);
        let b4r = *b.at(row + 4);
        let mut o0 = b0r ^ ((b1r ^ NOTMASK) & b2r);
        if yy == 0 {
            o0 = o0 ^ rc;
        }
        out.append(o0);
        out.append(b1r ^ ((b2r ^ NOTMASK) & b3r));
        out.append(b2r ^ ((b3r ^ NOTMASK) & b4r));
        out.append(b3r ^ ((b4r ^ NOTMASK) & b0r));
        out.append(b4r ^ ((b0r ^ NOTMASK) & b1r));
        yy += 1;
    }
    out
}

fn keccak_f1600(state: Array<u64>) -> Array<u64> {
    let rc = round_constants();
    let mut s = state;
    let mut r: u32 = 0;
    while r != 24 {
        s = keccak_round(s.span(), *rc.at(r));
        r += 1;
    }
    s
}

fn zeros25() -> Array<u64> {
    let mut a = array![];
    let mut i: u32 = 0;
    while i != 25 {
        a.append(0_u64);
        i += 1;
    }
    a
}

fn byte_at(pb: @Array<u8>, idx: u32, last_idx: u32) -> u64 {
    let raw: u64 = (*pb.at(idx)).into();
    if idx == last_idx {
        raw | 0x80
    } else {
        raw
    }
}

/// pack 8 little-endian bytes starting at `off` into a u64 lane
fn pack_lane(pb: @Array<u8>, off: u32, last_idx: u32) -> u64 {
    let mut lane: u64 = 0;
    let mut mul: u64 = 1;
    let mut k: u32 = 0;
    while k != 8 {
        lane = lane + byte_at(pb, off + k, last_idx) * mul;
        if k != 7 {
            mul = mul * 256;
        }
        k += 1;
    }
    lane
}

/// SHAKE256 returning `out_lanes` 64-bit output lanes.
pub fn shake256_lanes(msg: Array<u8>, out_lanes: u32) -> Array<u64> {
    let mlen = msg.len();
    let num_blocks = mlen / 136 + 1;
    let padded_len = num_blocks * 136;

    // build padded byte stream: msg || 0x1F || 0x00.. ; last byte |= 0x80 handled in byte_at
    let mut pb = array![];
    let mut i: u32 = 0;
    while i != padded_len {
        if i < mlen {
            pb.append(*msg.at(i));
        } else if i == mlen {
            pb.append(0x1f_u8);
        } else {
            pb.append(0_u8);
        }
        i += 1;
    }
    let last_idx = padded_len - 1;

    // absorb
    let mut state = zeros25();
    let mut blk: u32 = 0;
    while blk != num_blocks {
        let base = blk * 136;
        let mut ns = array![];
        let mut li: u32 = 0;
        while li != 25 {
            if li < 17 {
                let lane = pack_lane(@pb, base + li * 8, last_idx);
                ns.append(*state.at(li) ^ lane);
            } else {
                ns.append(*state.at(li));
            }
            li += 1;
        }
        state = keccak_f1600(ns);
        blk += 1;
    }

    // squeeze (rate = 17 lanes)
    let mut out = array![];
    let mut produced: u32 = 0;
    let mut cur = state;
    let mut done = false;
    while !done {
        let mut k: u32 = 0;
        while k != 17 {
            if produced == out_lanes {
                break;
            }
            out.append(*cur.at(k));
            produced += 1;
            k += 1;
        }
        if produced == out_lanes {
            done = true;
        } else {
            cur = keccak_f1600(cur);
        }
    }
    out
}
