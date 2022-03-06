#![no_std]

use elrond_wasm::*;

elrond_wasm::imports!();

#[elrond_wasm::derive::contract]
pub trait Simple {
    /// Constructor
    #[init]
    fn init(&self) {
        self.state().set(BigUint::zero());
    }

    /// Internal Values
    #[storage_mapper("state")]
    fn state(&self) -> SingleValueMapper<BigUint>;


    #[storage_mapper("mt_root_hash")]
    fn mt_root_hash(&self) -> SingleValueMapper<H256>;


    /// Events
    #[event("RootHashChanged")]
    fn root_hash_changed(&self);

    #[event("StateChanged")]
    fn state_changed(&self, state: BigUint);

    /// Public Methods
    #[endpoint]
    fn update_root_hash(&self, hash: H256) -> SCResult<()> {
        only_owner!(self, "Caller must be owner");
        require!(&hash != &H256::zero(), "hash must not be zero");

        self.mt_root_hash().set(&hash);
        self.root_hash_changed();

        Ok(())
    }

    #[view]
    fn get_state(&self) -> BigUint {
        self.state().get()
    }

    #[view]
    fn get_root_hash(&self) -> H256 {
        self.mt_root_hash().get()
    }

    #[endpoint]
    fn set_state(&self, _state: BigUint, proofs: Vec<[u8; 32]>) -> SCResult<()> {
        let requested_address = self.blockchain().get_caller().to_address();
        let address = self.crypto().keccak256_legacy_alloc(requested_address.as_bytes());

        let permission = self.verify(address, proofs);
        require!(permission == true, "Permission Denied");

        self.state().set(&_state);
        self.state_changed(_state);

        Ok(())
    }

    /// Private Methods
    fn verify(&self, leaf: H256, proofs: Vec<[u8; 32]>) -> bool {
        let mut computed_hash: H256 = leaf.clone();
        for i in 0..proofs.len() {
            let proof_element = proofs[i];

            if computed_hash.as_bytes() <= &proof_element {
                let result = self.get_abi_encoded(computed_hash.as_bytes(), &proof_element);
                computed_hash  = self.crypto().keccak256_legacy_alloc(result.as_slice());
            } else {
                let result = self.get_abi_encoded( &proof_element, computed_hash.as_bytes());
                computed_hash  = self.crypto().keccak256_legacy_alloc(result.as_slice());
            }
        }

        computed_hash == self.mt_root_hash().get()
    }

    fn get_abi_encoded(&self, left: &[u8], right: &[u8]) -> Vec<u8> {
        let mut raw_key: Vec<u8> = Vec::with_capacity(64);
        raw_key.extend_from_slice(left);
        raw_key.extend_from_slice(right);

        raw_key
    }
}