//! Falcon-512 signature verification for Starknet.
//!
//! Build order (see repo README):
//!   zq        — modular arithmetic mod q = 12289          [M1, seed]
//!   shake256  — pure-Cairo SHAKE256 (KAT-verified)         [M3, done]
//!   ntt       — number-theoretic transform (codegen'd)     [M2, todo]
//!   hash_to_point, packing, falcon — verifier             [M3/M4, todo]

pub mod zq;
pub mod shake256;
pub mod hash_to_point;
pub mod packing;
pub mod verify;

pub mod ntt_generated;
pub mod ntt512;
pub mod ntt_zetas;
pub mod ntt_looped;
