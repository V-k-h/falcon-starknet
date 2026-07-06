//! On-chain Falcon-512 verifier contract.
//!
//! Uses `verify_hint_512_looped` — the compact looped NTT — so the whole
//! contract class fits Starknet's max contract class size. (The fully-unrolled
//! `ntt_512` is ~10x cheaper per transform but its ~300K-felt body is ~3.7x over
//! the cap and cannot be declared; the looped NTT is bit-for-bit identical and
//! deployable.) A contract class's Sierra includes only functions reachable from
//! its entrypoints, so the pure-Cairo SHAKE256 hash-to-point is NOT pulled in.
//!
//! `verify` takes four 512-coefficient polynomials in [0, q); both forward NTTs
//! and the hint/norm core run on-chain.

#[starknet::interface]
pub trait IFalconVerifier<TContractState> {
    fn verify(
        self: @TContractState,
        s2: Array<felt252>,
        pk_ntt: Array<felt252>,
        mul_hint: Array<felt252>,
        msg_point: Array<felt252>,
    ) -> bool;

    /// Self-contained standard verify: hashes the FN-DSA framed bytes on-chain
    /// (interoperable SHAKE-256) to the challenge, then verifies.
    fn verify_full(
        self: @TContractState,
        framed: Array<u8>,
        s2: Array<felt252>,
        pk_ntt: Array<felt252>,
        mul_hint: Array<felt252>,
    ) -> bool;
}

#[starknet::contract]
pub mod FalconVerifier {
    use falcon::verify::{verify_hint_512_looped, verify_full_shake};

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl FalconVerifierImpl of super::IFalconVerifier<ContractState> {
        fn verify(
            self: @ContractState,
            s2: Array<felt252>,
            pk_ntt: Array<felt252>,
            mul_hint: Array<felt252>,
            msg_point: Array<felt252>,
        ) -> bool {
            verify_hint_512_looped(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
        }

        fn verify_full(
            self: @ContractState,
            framed: Array<u8>,
            s2: Array<felt252>,
            pk_ntt: Array<felt252>,
            mul_hint: Array<felt252>,
        ) -> bool {
            verify_full_shake(framed, s2.span(), pk_ntt.span(), mul_hint.span())
        }
    }
}
