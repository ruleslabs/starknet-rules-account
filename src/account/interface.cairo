use array::{ SpanSerde };
use starknet::account::Call;

const ISRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;

#[starknet::interface]
trait ISRC6<TContractState> {
  fn __execute__(self: @TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
  fn __validate__(self: @TContractState, calls: Array<Call>) -> felt252;
  fn is_valid_signature(self: @TContractState, hash: felt252, signature: Array<felt252>) -> felt252;
}

#[starknet::interface]
trait ISRC6Camel<TContractState> {
  fn isValidSignature(self: @TContractState, hash: felt252, signature: Array<felt252>) -> felt252;
}

#[starknet::interface]
trait IDeclarer<TContractState> {
  fn __validate_declare__(self: @TContractState, class_hash: felt252) -> felt252;
}

#[starknet::interface]
trait IDeployer<TContractState> {
  fn __validate_deploy__(
    self: @TContractState,
    class_hash: felt252,
    contract_address_salt: felt252,
    signer_public_key_: felt252,
    guardian_public_key_: felt252
  ) -> felt252;
}

#[starknet::interface]
trait IAccount<TContractState> {
  fn get_version(self: @TContractState) -> felt252;

  fn get_signer_public_key(self: @TContractState) -> felt252;

  fn set_signer_public_key(ref self: TContractState, new_public_key: felt252);
}

#[starknet::interface]
trait ISecureAccount<TContractState> {
  fn get_guardian_public_key(self: @TContractState) -> felt252;

  fn get_signer_escape_activation_date(self: @TContractState) -> u64;

  fn set_guardian_public_key(ref self: TContractState, new_public_key: felt252);

  fn trigger_signer_escape(ref self: TContractState);

  fn cancel_escape(ref self: TContractState);

  fn escape_signer(ref self: TContractState, new_public_key: felt252);
}
