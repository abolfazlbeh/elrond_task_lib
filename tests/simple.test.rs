use simple::*;
use elrond_wasm::types::{BigUint, H256};
use elrond_wasm_debug::{assert_sc_error, DebugApi};


#[test]
fn test_add_address_and_verify() {
    let address2 = "f17f52151EbEF6C7334FAD080c5704D77216b732";
    let address3 = "C5fdf4076b8F3A5357c5E395ab970B5B54098Fef";
    let address1 = "821aEa9a577a9b44299B9c15c88cf3087F3b5544";


    let mut t: MerkleTree = MerkleTree::build(&[address2, address3, address1], true);

    let _ = DebugApi::dummy();
    let simple = simple::contract_obh::<DebugApi>();

    simple.init();
    assert_eq!(BigUint::zero(), simple.get_state());

    match simple.update_root_hash(H256::from_slice(t.root_hash_str().as_bytes())) {
        Ok(_) => println!("root hash is updated"),
        Err(e) => assert_sc_error!(e),
    };

    match simple.set_state(BigUint::from(2), t.proofs()) {
        Ok(_) => println!("state is updated"),
        Err(e) => assert_sc_error!(e),
    };

    assert_eq!(BigUint::from(2), simple.get_state());
}