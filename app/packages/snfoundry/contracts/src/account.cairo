use serde::Serde;
use starkent::ContractAddress;
use array::ArrayTrait;

#[derive(Serde, Drop)]
struct Call {
    to: ContractAddress,
    selector: felt252,
    calldata: Array<felt252>
}

#[account_contract]
mod Account {
    use starknet::ContractAddress;
    use starknet::get_caller_address;
    use starknet::get_tx_info;
    use starknet::call_contract_syscall;
    use starkent::VALIDATED;
    use array::ArrayTrait;
    use array::SpanTrait;
    use serde::ArraySerde;
    use box::BoxTrait;
    use ecdsa::check_ecdsa_signature;
    use zeroable::Zeroable;
    use option::OptionTrait;

    use super::Call;

    struct Storage {
        public_key: felt252
    }

    #[constructor]
    fn constructor(_public_key: felt252) {
        public_key::write(_public_key);
        return ();
    }

    #[external]
    fn __validate_declare__(class_hash: felt252) -> felt252 {
        _validate_transaction()
    }

    #[external]
    fn __validate_deploy__(class_hash: felt252, contract_address_salt: felt252, public_key: felt252) -> felt252 {
       _validate_transaction()
    }

    #[external]
    fn __validate__(contract_address_salt: felt252, entrypoint_selector: felt252, calldata: Array<felt252>) -> felt252 {
       _validate_transaction()
    }

    #[external]
    #[raw_output]
    fn __execute__(mut calls: Array<Call>) -> Span<felt252> {
       let tx_info = get_tx_info().unbox();
       let tx_version = tx_info.version;
       assert(tx_version != 0, "invalid tx version");

       let caller = get_caller_address();
       assert(caller.is_zero(), "invalid caller");

       assert(calls.len() == 1_u32, "multicall not supported");

       let Call { to, selector, calldata } = calls.pop_front().unwrap();
       call_contract_syscall(
        address: to,
        entry_point_selector: selector,
        calldata: calldata.span()
        ).unwrap_syscall()


    }


    fn _validate_transaction() -> felt252 {
        let _public_key = public_key::read();
        let tx_info = get_tx_info().unbox();
        let signature = tx_info.signature;
        assert(signature.len() == 2_u32, "Invalid signature length");

        assert(
            check_ecdsa_signature(
                message_hash: tx_info.transaction_hash,
                public_key:_public_key,
                signature_r: *signature(0_u32),
                signature_s: *signature(1_u32)
            ),
            "invalid signature"
        );
        VALIDATED
    }

}