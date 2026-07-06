//! On-chain Falcon-512 verifier contract — and a code-SIZE probe.
//!
//! A contract class's Sierra includes ONLY functions reachable from its
//! entrypoints, so this wraps `verify_hint_512` (both forward NTTs + hint/norm
//! core) WITHOUT the pure-Cairo SHAKE256. Even so, the FULLY UNROLLED ntt_512
//! makes the class ~3.7x larger than Starknet's max contract class size — see
//! the size lines printed by `scarb build`. That is the decisive result: the
//! unrolled NTT is cheap in raw VM gas but NOT deployable as a contract; a
//! looped/partially-unrolled NTT is required to fit the code-size cap.
//!
//! `ntt_once` isolates a single ntt_512 body so `scarb build` reports the code
//! size of ONE unrolled transform against the 81,920-felt cap.

#[starknet::interface]
pub trait IFalconVerifier<TContractState> {
    /// Full verify: both forward NTTs (unrolled) + hint/norm core.
    fn verify(
        self: @TContractState,
        s2: Array<felt252>,
        pk_ntt: Array<felt252>,
        mul_hint: Array<felt252>,
        msg_point: Array<felt252>,
    ) -> bool;

    /// Size probe: one unrolled ntt_512 (returns coefficient 0).
    fn ntt_once(self: @TContractState, input: Array<felt252>) -> felt252;
}

#[starknet::contract]
pub mod FalconVerifier {
    use falcon::verify::verify_hint_512;
    use falcon::ntt512::ntt_512;

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
            verify_hint_512(s2.span(), pk_ntt.span(), mul_hint.span(), msg_point.span())
        }

        fn ntt_once(self: @ContractState, input: Array<felt252>) -> felt252 {
            let out = ntt_512(input.span());
            *out.at(0)
        }
    }
}
