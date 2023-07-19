use array::{ Array, SpanSerde };

const TRANSACTION_VERSION: felt252 = 1;
// 2 ** 128 + TRANSACTION_VERSION
const QUERY_VERSION: felt252 = 0x100000000000000000000000000000001;

#[starknet::interface]
trait AccountABI<T> {
  #[view]
  fn get_signer_public_key(self: @T) -> felt252;

  #[view]
  fn is_valid_signature(self: @T, message: felt252, signature: Span<felt252>) -> u32;

  #[view]
  fn supports_interface(self: @T, interface_id: u32) -> bool;

  #[external]
  fn upgrade(ref self: T, new_implementation: starknet::ClassHash);

  #[external]
  fn __execute__(ref self: T, calls: Array<starknet::account::Call>) -> Array<Span<felt252>>;

  #[external]
  fn __validate__(ref self: T, calls: Array<starknet::account::Call>) -> felt252;

  #[external]
  fn __validate_declare__(ref self: T, class_hash: felt252) -> felt252;

  #[external]
  fn __validate_deploy__(
    ref self: T,
    class_hash: felt252,
    contract_address_salt: felt252,
    signer_public_key_: felt252,
    guardian_public_key_: felt252
  ) -> felt252;

  #[external]
  fn set_signer_public_key(ref self: T, new_signer_public_key: felt252);
}

#[starknet::contract]
mod Account {
  use array::{ ArrayTrait, SpanTrait, SpanSerde };
  use box::BoxTrait;
  use ecdsa::check_ecdsa_signature;
  use option::OptionTrait;
  use traits::Into;
  use zeroable::Zeroable;
  use integer::U64Zeroable;
  use rules_utils::utils::traits::BoolIntoU8;

  // locals
  use rules_utils::introspection::erc165::{ ERC165, IERC165 };
  use rules_account::account;
  use super::{ QUERY_VERSION, TRANSACTION_VERSION };

  const TRIGGER_ESCAPE_SIGNER_SELECTOR: felt252 =
    823970870440803648323000253851988489761099050950583820081611025987402410277;
  const ESCAPE_SIGNER_SELECTOR: felt252 =
    578307412324655990419134484880427622068887477430675222732446709420063579565;
  const SUPPORTS_INTERFACE_SELECTOR: felt252 = 0xfe80f537b66d12a00b6d3c072b44afbb716e78dde5c3f0ef116ee93d3e3283;

  const CONTRACT_VERSION: felt252 = '1.0.0';
  const ESCAPE_SECURITY_PERIOD: u64 = 259200; // 3d * 24h * 60m * 60s

  //
  // Storage
  //

  #[storage]
  struct Storage {
    _signer_public_key: felt252,
    _guardian_public_key: felt252,
    _signer_escape_activation_date: u64,
  }

  //
  // Events
  //

  #[event]
  #[derive(Drop, starknet::Event)]
  enum Event {
    AccountUpgraded: AccountUpgraded,
    AccountInitialized: AccountInitialized,
    SignerPublicKeyChanged: SignerPublicKeyChanged,
    GuardianPublicKeyChanged: GuardianPublicKeyChanged,
    SignerEscapeTriggered: SignerEscapeTriggered,
    SignerEscaped: SignerEscaped,
    EscapeCanceled: EscapeCanceled,
  }

  #[derive(Drop, starknet::Event)]
  struct AccountUpgraded {
    new_implementation: starknet::ClassHash,
  }

  #[derive(Drop, starknet::Event)]
  struct AccountInitialized {
    signer_public_key: felt252,
    guardian_public_key: felt252,
  }

  #[derive(Drop, starknet::Event)]
  struct SignerPublicKeyChanged {
    new_public_key: felt252,
  }

  #[derive(Drop, starknet::Event)]
  struct GuardianPublicKeyChanged {
    new_public_key: felt252,
  }

  #[derive(Drop, starknet::Event)]
  struct SignerEscapeTriggered {
    active_at: u64,
  }

  #[derive(Drop, starknet::Event)]
  struct SignerEscaped {
    new_public_key: felt252,
  }

  #[derive(Drop, starknet::Event)]
  struct EscapeCanceled { }

  //
  // Modifiers
  //

  /// Modifiers (internal functions)
  #[generate_trait]
  impl ModifierImpl of ModifierTrait {
    fn _only_self(self: @ContractState) {
      let caller = starknet::get_caller_address();
      let contract = starknet::get_contract_address();
      assert(contract == caller, 'Account: unauthorized');
    }

    fn _non_reentrant(self: @ContractState) {
      let caller = starknet::get_caller_address();
      assert(caller.is_zero(), 'Account: no reentrant call');
    }

    fn _correct_tx_version(self: @ContractState) {
      let tx_info = starknet::get_tx_info().unbox();
      let version = tx_info.version;

      if (version != TRANSACTION_VERSION) {
        assert(version == QUERY_VERSION, 'Account: invalid tx version');
      }
    }
  }

  //
  // Constructor
  //

  #[constructor]
  fn constructor(ref self: ContractState, signer_public_key_: felt252, guardian_public_key_: felt252) {
    self.initializer(signer_public_key_, guardian_public_key_);
  }

  //
  // Account impl
  //

  #[external(v0)]
  impl AccountImpl of account::interface::IAccount<ContractState> {
    fn get_version(self: @ContractState) -> felt252 {
      CONTRACT_VERSION
    }

    fn is_valid_signature(self: @ContractState, message: felt252, signature: Span<felt252>) -> u32 {
      if (self._is_valid_signature(:message, :signature, public_key: self._signer_public_key.read())) {
        account::interface::ERC1271_VALIDATED
      } else {
        0_u32
      }
    }

    fn supports_interface(self: @ContractState, interface_id: u32) -> bool {
      if (interface_id == account::interface::IACCOUNT_ID) {
        true
      } else {
        let erc165_self = ERC165::unsafe_new_contract_state();

        erc165_self.supports_interface(:interface_id)
      }
    }

    fn get_signer_public_key(self: @ContractState) -> felt252 {
      self._signer_public_key.read()
    }

    fn __execute__(ref self: ContractState, calls: Array<starknet::account::Call>) -> Array<Span<felt252>> {
      // Modifiers
      self._non_reentrant();
      self._correct_tx_version();

      // Body
      self._execute_calls(:calls)
    }

    fn __validate__(ref self: ContractState, calls: Array<starknet::account::Call>) -> felt252 {
      self._validate_transaction_with_calls(:calls)
    }

    fn __validate_declare__(ref self: ContractState, class_hash: felt252) -> felt252 {
      self._validate_transaction()
    }

    fn set_signer_public_key(ref self: ContractState, new_public_key: felt252) {
      // Modifiers
      self._only_self();

      // Body
      self._signer_public_key.write(new_public_key);

      // Events
      self.emit(
        Event::SignerPublicKeyChanged(
          SignerPublicKeyChanged { new_public_key }
        )
      );
    }
  }

  //
  // Secure account impl
  //

  #[external(v0)]
  impl SecureAccount of account::interface::ISecureAccount<ContractState> {
    fn get_guardian_public_key(self: @ContractState, ) -> felt252 {
      self._guardian_public_key.read()
    }

    fn get_signer_escape_activation_date(self: @ContractState, ) -> u64 {
      self._signer_escape_activation_date.read()
    }

    fn __validate_deploy__(
      ref self: ContractState,
      class_hash: felt252,
      contract_address_salt: felt252,
      signer_public_key_: felt252,
      guardian_public_key_: felt252
    ) -> felt252 {
      starknet::VALIDATED
    }

    fn set_guardian_public_key(ref self: ContractState, new_public_key: felt252) {
      // Modifiers
      self._only_self();

      // Body
      self._guardian_public_key.write(new_public_key);

      // Events
      self.emit(
        Event::GuardianPublicKeyChanged(
          GuardianPublicKeyChanged { new_public_key }
        )
      );
    }

    fn trigger_signer_escape(ref self: ContractState) {
      // Modifiers
      self._only_self();

      // Body
      let block_timestamp = starknet::get_block_timestamp();
      let active_date = block_timestamp + ESCAPE_SECURITY_PERIOD;

      self._signer_escape_activation_date.write(active_date);

      // Events
      self.emit(
        Event::SignerEscapeTriggered(
          SignerEscapeTriggered { active_at: active_date }
        )
      );
    }

    fn cancel_escape(ref self: ContractState) {
      // Modifiers
      self._only_self();

      // Body
      let current_escape = self._signer_escape_activation_date.read();
      assert(current_escape.is_non_zero(), 'Account: no escape to cancel');

      self._signer_escape_activation_date.write(0);

      // Events
      self.emit(
        Event::EscapeCanceled(
          EscapeCanceled { }
        )
      );
    }

    fn escape_signer(ref self: ContractState, new_public_key: felt252) {
      // Modifiers
      self._only_self();

      // Body

      // Check if an escape is active
      let current_escape_activation_date = self._signer_escape_activation_date.read();
      let block_timestamp = starknet::get_block_timestamp();

      assert(current_escape_activation_date.is_non_zero(), 'Account: no escape');
      assert(current_escape_activation_date <= block_timestamp, 'Account: invalid escape');

      // Clear escape
      self._signer_escape_activation_date.write(0);

      // Check if new public key is valid
      assert(new_public_key.is_non_zero(), 'Account: new pk cannot be null');

      // Update signer public key
      self._signer_public_key.write(new_public_key);

      // Events
      self.emit(
        Event::SignerEscaped(
          SignerEscaped { new_public_key }
        )
      );
    }
  }

  //
  // Upgrade impl
  //

  #[generate_trait]
  #[external(v0)]
  impl UpgradeImpl of UpgradeTrait {
    fn upgrade(ref self: ContractState, new_implementation: starknet::ClassHash) {
      // Modifiers
      self._only_self();

      // Body

      // Check if new impl is an account
      let mut calldata = ArrayTrait::new();
      calldata.append(account::interface::IACCOUNT_ID.into());

      let ret_data = starknet::library_call_syscall(
        class_hash: new_implementation,
        function_selector: SUPPORTS_INTERFACE_SELECTOR,
        calldata: calldata.span()
      ).unwrap_syscall();

      assert(
        (ret_data.len() == 1) & (*ret_data.at(0) == Into::<bool, u8>::into(true).into()),
        'Account: invalid implementation'
      );

      // set new impl
      starknet::replace_class_syscall(new_implementation);

      // Events
      self.emit(
        Event::AccountUpgraded(
          AccountUpgraded { new_implementation }
        )
      );
    }
  }

  //
  // Internals
  //

  /// Helpers (internal functions)
  #[generate_trait]
  impl HelperImpl of HelperTrait {

    // Init

    fn initializer(ref self: ContractState, signer_public_key_: felt252, guardian_public_key_: felt252) {
      self._signer_public_key.write(signer_public_key_);
      self._guardian_public_key.write(guardian_public_key_);

      // Events
      self.emit(
        Event::AccountInitialized(
          AccountInitialized { signer_public_key: signer_public_key_, guardian_public_key: guardian_public_key_ }
        )
      );
    }

    // Validate

    fn _validate_transaction_with_calls(ref self: ContractState, calls: Array<starknet::account::Call>) -> felt252 {
      let tx_info = starknet::get_tx_info().unbox();
      let tx_hash = tx_info.transaction_hash;
      let signature = tx_info.signature;
      let account_contract_address = tx_info.account_contract_address;

      // check the tx signature against the signer pk by default
      let mut public_key: felt252 = self._signer_public_key.read();

      if (calls.len() == 1) {
        if (*calls.at(0).to == account_contract_address) {
          let guardian_condition =
            (*calls.at(0).selector - ESCAPE_SIGNER_SELECTOR) * (*calls.at(0).selector - TRIGGER_ESCAPE_SIGNER_SELECTOR);

          if (guardian_condition.is_zero()) {
            // if calls are a single escape_signer or trigger_signer_escape,
            // we check tx signature against the guardian pk
            public_key = self._guardian_public_key.read()
          }
        }
      }

      // signature check
      assert(self._is_valid_signature(message: tx_hash, :signature, :public_key), 'Account: invalid signature');

      starknet::VALIDATED
    }

    fn _validate_transaction(self: @ContractState) -> felt252 {
      let tx_info = starknet::get_tx_info().unbox();
      let tx_hash = tx_info.transaction_hash;
      let signature = tx_info.signature;

      assert(
        self._is_valid_signature(message: tx_hash, :signature, public_key: self._signer_public_key.read()),
        'Account: invalid signature'
      );

      starknet::VALIDATED
    }

    fn _is_valid_signature(self: @ContractState, message: felt252, signature: Span<felt252>, public_key: felt252) -> bool {
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

    fn _execute_calls(self: @ContractState, mut calls: Array<starknet::account::Call>) -> Array<Span<felt252>> {
      let mut res = ArrayTrait::new();

      loop {
        match calls.pop_front() {
          Option::Some(call) => {
            let _res = self._execute_single_call(call);
            res.append(_res);
          },
          Option::None(_) => {
            break ();
          },
        };
      };

      res
    }

    fn _execute_single_call(self: @ContractState, call: starknet::account::Call) -> Span<felt252> {
      let starknet::account::Call { to, selector, calldata } = call;
      starknet::call_contract_syscall(to, selector, calldata.span()).unwrap_syscall()
    }
  }
}
