//! Deploy-path measurement of the unrolled Falcon-512 verifier.
//!
//! Declares + deploys `FalconVerifier` and invokes `verify` on a REAL fn-dsa
//! Falcon-512 signature. The entrypoint computes BOTH forward NTTs (unrolled
//! ntt_512) and the hint/norm core — the full on-chain verify — so the reported
//! l2_gas is the true deploy-path cost, directly comparable to published
//! Falcon-on-Starknet gas figures.
use snforge_std::fs::{FileTrait, read_json};
use snforge_std::{declare, ContractClassTrait, DeclareResultTrait};
use verifier_contract::{IFalconVerifierDispatcher, IFalconVerifierDispatcherTrait};

#[derive(Drop, Serde)]
struct V {
    s2: Array<felt252>,
    pk_ntt: Array<felt252>,
    mul_hint: Array<felt252>,
    msg_point: Array<felt252>,
    a: Array<felt252>,
    b: Array<felt252>,
}

fn deploy() -> IFalconVerifierDispatcher {
    let contract = declare("FalconVerifier").unwrap().contract_class();
    let (addr, _) = contract.deploy(@array![]).unwrap();
    IFalconVerifierDispatcher { contract_address: addr }
}

// Real deploy-path measurement: the contract uses the LOOPED NTT, which fits
// Starknet's contract class-size cap. Declares + deploys FalconVerifier and
// invokes `verify` (both forward NTTs + hint/norm core) on a real fn-dsa
// Falcon-512 signature. The reported l2_gas is the true on-chain verify cost.
#[test]
fn deploy_and_full_verify_real_signature() {
    let file = FileTrait::new("tests/data/verify512_kat.json");
    let serialized = read_json(@file);
    let mut span = serialized.span();
    let _header = span.pop_front();
    let v: V = Serde::deserialize(ref span).expect('deserialize failed');

    let dispatcher = deploy();
    let ok = dispatcher.verify(v.s2, v.pk_ntt, v.mul_hint, v.msg_point);
    assert!(ok, "full on-chain verify_hint_512 must accept a real signature");
}
