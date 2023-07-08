use array::ArrayTrait;
use array::SpanTrait;
use starknet::ContractAddress;

const IACCOUNT_ID: u32 = 0xa66bd575_u32;
const ERC1271_VALIDATED: u32 = 0x1626ba7e_u32;

#[starknet::interface]
trait IAccount<TContractState> {
  fn get_version(self: @TContractState) -> felt252;

  fn get_signer_public_key(self: @TContractState) -> felt252;

  fn is_valid_signature(self: @TContractState, message: felt252, signature: Span<felt252>) -> u32;

  fn supports_interface(self: @TContractState, interface_id: u32) -> bool;

  fn __execute__(ref self: TContractState, calls: Array<starknet::account::Call>) -> Array<Span<felt252>>;

  fn __validate__(ref self: TContractState, calls: Array<starknet::account::Call>) -> felt252;

  fn __validate_declare__(ref self: TContractState, class_hash: felt252) -> felt252;

  fn set_signer_public_key(ref self: TContractState, new_public_key: felt252);
}

#[starknet::interface]
trait ISecureAccount<TContractState> {
  fn get_guardian_public_key(self: @TContractState) -> felt252;

  fn get_signer_escape_activation_date(self: @TContractState) -> u64;

  fn __validate_deploy__(
    ref self: TContractState,
    class_hash: felt252,
    contract_address_salt: felt252,
    signer_public_key_: felt252,
    guardian_public_key_: felt252
  ) -> felt252;

  fn set_guardian_public_key(ref self: TContractState, new_public_key: felt252);

  fn trigger_signer_escape(ref self: TContractState);

  fn cancel_escape(ref self: TContractState);

  fn escape_signer(ref self: TContractState, new_public_key: felt252);
}
