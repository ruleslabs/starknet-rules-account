use array::Array;

use rules_account::account::interface::Call;
use rules_account::utils::serde::SpanSerde;

const TRANSACTION_VERSION: felt252 = 1;
// 2 ** 128 + TRANSACTION_VERSION
const QUERY_VERSION: felt252 = 0x100000000000000000000000000000001;

#[abi]
trait AccountABI {
  #[view]
  fn get_signer_public_key() -> felt252;

  #[view]
  fn is_valid_signature(message: felt252, signature: Array<felt252>) -> u32;

  #[view]
  fn supports_interface(interface_id: u32) -> bool;

  #[external]
  fn upgrade(new_implementation: starknet::ClassHash);

  #[external]
  fn __execute__(calls: Array<Call>) -> Array<Span<felt252>>;

  #[external]
  fn __validate__(calls: Array<Call>) -> felt252;

  #[external]
  fn __validate_declare__(class_hash: felt252) -> felt252;

  #[external]
  fn __validate_deploy__(
    class_hash: felt252,
    contract_address_salt: felt252,
    signer_public_key_: felt252,
    guardian_public_key_: felt252
  ) -> felt252;

  #[external]
  fn set_signer_public_key(new_signer_public_key: felt252);
}

#[account_contract]
mod Account {
  use array::{ ArrayTrait, SpanTrait };
  use box::BoxTrait;
  use ecdsa::check_ecdsa_signature;
  use serde::ArraySerde;
  use option::OptionTrait;
  use traits::Into;
  use zeroable::Zeroable;

  // locals
  use rules_account::introspection::erc165::ERC165;
  use rules_account::utils::zeroable::U64Zeroable;
  use rules_account::utils::into::BoolIntoU8;
  use rules_account::utils::serde::SpanSerde;
  use rules_account::account;
  use super::Call;
  use super::QUERY_VERSION;
  use super::TRANSACTION_VERSION;

  const TRIGGER_ESCAPE_SIGNER_SELECTOR: felt252 =
    823970870440803648323000253851988489761099050950583820081611025987402410277;
  const ESCAPE_SIGNER_SELECTOR: felt252 =
    578307412324655990419134484880427622068887477430675222732446709420063579565;
  const SUPPORTS_INTERFACE_SELECTOR: felt252 =
    1184015894760294494673613438913361435336722154500302038630992932234692784845;

  const CONTRACT_VERSION: felt252 = '1.0.0';
  const ESCAPE_SECURITY_PERIOD: u64 = 259200; // 3d * 24h * 60m * 60s

  //
  // Storage
  //

  struct Storage {
    _signer_public_key: felt252,
    _guardian_public_key: felt252,
    _signer_escape_activation_date: u64,
  }

  //
  // Events
  //

  #[event]
  fn AccountUpgraded(
    new_implementation: starknet::ClassHash,
  ) {}

  #[event]
  fn AccountInitialized(
    signer_public_key: felt252,
    guardian_public_key: felt252,
  ) {}

  #[event]
  fn SignerPublicKeyChanged(
    new_public_key: felt252
  ) {}

  #[event]
  fn GuardianPublicKeyChanged(
    new_public_key: felt252
  ) {}

  #[event]
  fn SignerEscapeTriggered(
    active_at: u64
  ) {}

  #[event]
  fn SignerEscaped(
    new_public_key: felt252
  ) {}

  #[event]
  fn EscapeCanceled() {}

  //
  // Modifiers
  //

  #[internal]
  fn _only_self() {
    let caller = starknet::get_caller_address();
    let self = starknet::get_contract_address();
    assert(self == caller, 'Account: unauthorized');
  }

  #[internal]
  fn _non_reentrant() {
    let caller = starknet::get_caller_address();
    assert(caller.is_zero(), 'Account: no reentrant call');
  }

  #[internal]
  fn _correct_tx_version() {
    let tx_info = starknet::get_tx_info().unbox();
    let version = tx_info.version;

    if (version != TRANSACTION_VERSION) {
      assert(version == QUERY_VERSION, 'Account: invalid tx version');
    }
  }

  //
  // Constructor
  //

  #[constructor]
  fn constructor(signer_public_key_: felt252, guardian_public_key_: felt252) {
    initializer(signer_public_key_, guardian_public_key_);
  }

  //
  // Interfaces impl
  //

  impl Account of account::interface::IAccount {
    fn get_signer_public_key() -> felt252 {
      _signer_public_key::read()
    }

    fn is_valid_signature(message: felt252, signature: Array<felt252>) -> u32 {
      if (_is_valid_signature(message, signature.span(), _signer_public_key::read())) {
        account::interface::ERC1271_VALIDATED
      } else {
        0_u32
      }
    }

    fn supports_interface(interface_id: u32) -> bool {
      if (interface_id == account::interface::IACCOUNT_ID) {
        true
      } else {
        ERC165::supports_interface(interface_id)
      }
    }

    fn __execute__(calls: Array<Call>) -> Array<Span<felt252>> {
      _execute_calls(:calls)
    }

    fn __validate__(calls: Array<Call>) -> felt252 {
      _validate_transaction_with_calls(:calls)
    }

    fn __validate_declare__(class_hash: felt252) -> felt252 {
      _validate_transaction()
    }

    fn set_signer_public_key(new_public_key: felt252) {
      _signer_public_key::write(new_public_key);

      // Events
      SignerPublicKeyChanged(:new_public_key);
    }
  }

  impl SecureAccount of account::interface::ISecureAccount {
    fn get_guardian_public_key() -> felt252 {
      _guardian_public_key::read()
    }

    fn get_signer_escape_activation_date() -> u64 {
      _signer_escape_activation_date::read()
    }

    fn __validate_deploy__(
      class_hash: felt252,
      contract_address_salt: felt252,
      signer_public_key_: felt252,
      guardian_public_key_: felt252
    ) -> felt252 {
      _validate_transaction()
    }

    fn set_guardian_public_key(new_public_key: felt252) {
      _guardian_public_key::write(new_public_key);

      // Events
      GuardianPublicKeyChanged(:new_public_key);
    }

    fn trigger_signer_escape() {
      let block_timestamp = starknet::get_block_timestamp();
      let active_date = block_timestamp + ESCAPE_SECURITY_PERIOD;

      _signer_escape_activation_date::write(active_date);

      // Events
      SignerEscapeTriggered(active_at: active_date);
    }

    fn cancel_escape() {
      let current_escape = _signer_escape_activation_date::read();
      assert(current_escape.is_non_zero(), 'Account: no escape to cancel');

      _signer_escape_activation_date::write(0);

      // Events
      EscapeCanceled();
    }

    fn escape_signer(new_public_key: felt252) {
      // Check if an escape is active
      let current_escape_activation_date = _signer_escape_activation_date::read();
      let block_timestamp = starknet::get_block_timestamp();

      assert(current_escape_activation_date.is_non_zero(), 'Account: no escape');
      assert(current_escape_activation_date <= block_timestamp, 'Account: invalid escape');

      // Clear escape
      _signer_escape_activation_date::write(0);

      // Check if new public key is valid
      assert(new_public_key.is_non_zero(), 'Account: new pk cannot be null');

      // Update signer public key
      _signer_public_key::write(new_public_key);

      // Events
      SignerEscaped(:new_public_key);
    }
  }

  //
  // Upgrade
  //

  // TODO: use Upgradeable impl with more custom call after upgrade
  #[external]
  fn upgrade(new_implementation: starknet::ClassHash) {
    // Modifiers
    _only_self();

    // Body

    // Check if new impl is an account
    let mut calldata = ArrayTrait::new();
    calldata.append(account::interface::IACCOUNT_ID.into());

    let ret_data = starknet::library_call_syscall(
      class_hash: new_implementation,
      function_selector: SUPPORTS_INTERFACE_SELECTOR,
      calldata: calldata.span()
    ).unwrap_syscall();

    assert(ret_data.len() == 1, 'Account: invalid implementation');
    assert(*ret_data.at(0) == Into::<bool, u8>::into(true).into(), 'Account: invalid implementation');

    // set new impl
    starknet::replace_class_syscall(new_implementation);

    // Events
    AccountUpgraded(:new_implementation);
  }

  //
  // Getters
  //

  #[view]
  fn get_version() -> felt252 {
    CONTRACT_VERSION
  }

  #[view]
  fn get_signer_public_key() -> felt252 {
    Account::get_signer_public_key()
  }

  #[view]
  fn get_guardian_public_key() -> felt252 {
    SecureAccount::get_guardian_public_key()
  }

  #[view]
  fn get_signer_escape_activation_date() -> u64 {
    SecureAccount::get_signer_escape_activation_date()
  }

  //
  // Setters
  //

  #[external]
  fn set_signer_public_key(new_public_key: felt252) {
    // Modifiers
    _only_self();

    // Body
    Account::set_signer_public_key(:new_public_key);
  }

  #[external]
  fn set_guardian_public_key(new_public_key: felt252) {
    // Modifiers
    _only_self();

    // Body
    SecureAccount::set_guardian_public_key(:new_public_key);
  }

  //
  // View
  //

  #[view]
  fn supports_interface(interface_id: u32) -> bool {
    Account::supports_interface(interface_id)
  }

  #[view]
  fn is_valid_signature(message: felt252, signature: Array<felt252>) -> u32 {
    Account::is_valid_signature(message, signature)
  }

  //
  // Account
  //

  #[external]
  fn __execute__(mut calls: Array<Call>) -> Array<Span<felt252>> {
    // Modifiers
    _non_reentrant();
    _correct_tx_version();

    // Body
    Account::__execute__(calls)
  }

  #[external]
  fn __validate__(mut calls: Array<Call>) -> felt252 {
    Account::__validate__(:calls)
  }

  #[external]
  fn __validate_declare__(class_hash: felt252) -> felt252 {
    Account::__validate_declare__(:class_hash)
  }

  #[external]
  fn __validate_deploy__(
    class_hash: felt252,
    contract_address_salt: felt252,
    signer_public_key_: felt252,
    guardian_public_key_: felt252
  ) -> felt252 {
    SecureAccount::__validate_deploy__(:class_hash, :contract_address_salt, :signer_public_key_, :guardian_public_key_)
  }

  // Secure Account

  #[external]
  fn trigger_signer_escape() {
    // Modifiers
    _only_self();

    // Body
    SecureAccount::trigger_signer_escape();
  }

  #[external]
  fn cancel_escape() {
    // Modifiers
    _only_self();

    // Body
    SecureAccount::cancel_escape();
  }

  #[external]
  fn escape_signer(new_public_key: felt252) {
    // Modifiers
    _only_self();

    // Body
    SecureAccount::escape_signer(:new_public_key);
  }

  //
  // Internals
  //

  // Init

  #[internal]
  fn initializer(signer_public_key_: felt252, guardian_public_key_: felt252) {
    _signer_public_key::write(signer_public_key_);
    _guardian_public_key::write(guardian_public_key_);

    // Events
    AccountInitialized(signer_public_key: signer_public_key_, guardian_public_key: guardian_public_key_);
  }

  // Validate

  #[internal]
  fn _validate_transaction_with_calls(calls: Array<Call>) -> felt252 {
    let tx_info = starknet::get_tx_info().unbox();
    let tx_hash = tx_info.transaction_hash;
    let signature = tx_info.signature;
    let account_contract_address = tx_info.account_contract_address;

    // check the tx signature against the signer pk by default
    let mut public_key: felt252 = get_signer_public_key();

    if (calls.len() == 1) {
      if (*calls.at(0).to == account_contract_address) {
        let guardian_condition =
          (*calls.at(0).selector - ESCAPE_SIGNER_SELECTOR) * (*calls.at(0).selector - TRIGGER_ESCAPE_SIGNER_SELECTOR);

        if (guardian_condition.is_zero()) {
          // if calls are a single escape_signer or trigger_signer_escape,
          // we check tx signature against the guardian pk
          public_key = get_guardian_public_key();
        }
      }
    }

    // signature check
    assert(_is_valid_signature(message: tx_hash, :signature, :public_key), 'Account: invalid signature');

    starknet::VALIDATED
  }

  #[internal]
  fn _validate_transaction() -> felt252 {
    let tx_info = starknet::get_tx_info().unbox();
    let tx_hash = tx_info.transaction_hash;
    let signature = tx_info.signature;

    assert(
      _is_valid_signature(message: tx_hash, :signature, public_key: _signer_public_key::read()),
      'Account: invalid signature'
    );

    starknet::VALIDATED
  }

  #[internal]
  fn _is_valid_signature(message: felt252, signature: Span<felt252>, public_key: felt252) -> bool {
    let valid_length = signature.len() == 2_u32;

    if valid_length {
      check_ecdsa_signature(
        message, public_key, *signature.at(0_u32), *signature.at(1_u32)
      )
    } else {
      false
    }
  }

  // Execute

  #[internal]
  fn _execute_calls(mut calls: Array<Call>) -> Array<Span<felt252>> {
    let mut res = ArrayTrait::new();
    loop {
      match calls.pop_front() {
        Option::Some(call) => {
          let _res = _execute_single_call(call);
          res.append(_res);
        },
        Option::None(_) => {
          break ();
        },
      };
    };
    res
  }

  #[internal]
  fn _execute_single_call(call: Call) -> Span<felt252> {
    let Call{to, selector, calldata } = call;
    starknet::call_contract_syscall(to, selector, calldata.span()).unwrap_syscall()
  }
}
