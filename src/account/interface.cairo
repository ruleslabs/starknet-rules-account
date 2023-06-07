use array::ArrayTrait;
use array::SpanTrait;
use starknet::ContractAddress;
use rules_account::utils::serde::SpanSerde;

const IACCOUNT_ID: u32 = 0xa66bd575_u32;
const ERC1271_VALIDATED: u32 = 0x1626ba7e_u32;

#[derive(Serde, Drop)]
struct Call {
  to: ContractAddress,
  selector: felt252,
  calldata: Array<felt252>
}

#[abi]
trait IAccount {
  fn get_signer_public_key() -> felt252;

  fn is_valid_signature(message: felt252, signature: Span<felt252>) -> u32;

  fn supports_interface(interface_id: u32) -> bool;

  fn __execute__(calls: Array<Call>) -> Array<Span<felt252>>;

  fn __validate__(calls: Array<Call>) -> felt252;

  fn __validate_declare__(class_hash: felt252) -> felt252;

  fn __validate_deploy__(class_hash: felt252, contract_address_salt: felt252, calldata: Array<felt252>) -> felt252;

  fn set_signer_public_key(new_public_key: felt252);
}

#[abi]
trait ISecureAccount {
  fn get_guardian_public_key() -> felt252;

  fn get_signer_escape_activation_date() -> u64;

  fn set_guardian_public_key(new_public_key: felt252);

  fn trigger_signer_escape();

  fn cancel_escape();

  fn escape_signer(new_public_key: felt252);
}
