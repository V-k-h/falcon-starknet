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

    /// Fully self-contained from the RAW public key: computes hpk =
    /// SHAKE256(vrfy_key)[0:64] on-chain, builds the framed input, hashes to the
    /// challenge, and verifies. Nothing hash-related is trusted from off-chain.
    fn verify_from_pk(
        self: @TContractState,
        vrfy_key: Array<u8>,
        nonce: Array<u8>,
        message: Array<u8>,
        s2: Array<felt252>,
        pk_ntt: Array<felt252>,
        mul_hint: Array<felt252>,
    ) -> bool;

    /// State-changing gate: verifies fully on-chain from the RAW public key and
    /// REVERTS if the signature is invalid, emitting `Verified` on success. A
    /// SUCCEEDED transaction to this entrypoint IS proof the signature is valid;
    /// a bad signature yields a reverted transaction.
    fn assert_verify_from_pk(
        ref self: TContractState,
        vrfy_key: Array<u8>,
        nonce: Array<u8>,
        message: Array<u8>,
        s2: Array<felt252>,
        pk_ntt: Array<felt252>,
        mul_hint: Array<felt252>,
    );
}

#[starknet::contract]
pub mod FalconVerifier {
    use falcon::verify::{verify_hint_512_looped, verify_full_shake, verify_full_from_pk};

    #[storage]
    struct Storage {}

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Verified: Verified,
    }

    /// Emitted only after a signature passes (the assert above it reverts otherwise).
    #[derive(Drop, starknet::Event)]
    struct Verified {
        ok: bool,
    }

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

        fn verify_from_pk(
            self: @ContractState,
            vrfy_key: Array<u8>,
            nonce: Array<u8>,
            message: Array<u8>,
            s2: Array<felt252>,
            pk_ntt: Array<felt252>,
            mul_hint: Array<felt252>,
        ) -> bool {
            verify_full_from_pk(
                vrfy_key, nonce, message, s2.span(), pk_ntt.span(), mul_hint.span(),
            )
        }

        fn assert_verify_from_pk(
            ref self: ContractState,
            vrfy_key: Array<u8>,
            nonce: Array<u8>,
            message: Array<u8>,
            s2: Array<felt252>,
            pk_ntt: Array<felt252>,
            mul_hint: Array<felt252>,
        ) {
            let ok = verify_full_from_pk(
                vrfy_key, nonce, message, s2.span(), pk_ntt.span(), mul_hint.span(),
            );
            assert!(ok, "invalid Falcon-512 signature");
            self.emit(Verified { ok });
        }
    }
}
