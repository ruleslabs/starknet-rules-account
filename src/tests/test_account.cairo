use zeroable::Zeroable;
use array::{ ArrayTrait, SpanTrait };
use traits::{ Into, TryInto };
use option::OptionTrait;
use serde::Serde;
use starknet::testing;
use starknet::class_hash::Felt252TryIntoClassHash;
use integer::U64Zeroable;

// locals
use rules_account::account::{ Account, QUERY_VERSION, TRANSACTION_VERSION };
use rules_account::account::Account::{ ModifierTrait, InternalTrait };
use rules_account::account::interface::{ IAccount, ISecureAccount, ISRC6, IDeclarer, IDeployer, ISRC6_ID };
use rules_utils::introspection::interface::{ ISRC5, ISRC5_ID };
use rules_account::tests::utils;
use rules_account::tests::mocks::erc20::ERC20;
use rules_account::tests::mocks::upgrade::{ ValidUpgrade, InvalidUpgrade };

// dispatchers
use rules_account::tests::mocks::erc20::{ IERC20Dispatcher, IERC20DispatcherTrait };
use rules_account::account::{ AccountABIDispatcher, AccountABIDispatcherTrait };

const SIGNER_PUBLIC_KEY: felt252 = 'signer public key';
const GUARDIAN_PUBLIC_KEY: felt252 = 'guardian public key';
const NEW_SIGNER_PUBKEY: felt252 = 'new signer pubkey';
const NEW_GUARDIAN_PUBKEY: felt252 = 'new guardian pubkey';
const TRANSFER_SELECTOR: felt252 = 0x83afd3f4caedc6eebf44246fe54e38c95e3179a5ec9ea81740eca5b482d12e;
const UPGRADE_SELECTOR: felt252 = 0xf2f7c15cbe06c8d94597cd91fd7f3369eae842359235712def5584f8d270cd;
const SALT: felt252 = 'salt';

#[derive(Drop)]
struct SignedTransactionData {
  private_key: felt252,
  public_key: felt252,
  transaction_hash: felt252,
  r: felt252,
  s: felt252,
  guardian: bool
}

fn BLOCK_TIMESTAMP() -> u64 {
  103374042_u64
}

fn CLASS_HASH() -> felt252 {
  Account::TEST_CLASS_HASH
}

fn ACCOUNT_ADDRESS() -> starknet::ContractAddress {
  starknet::contract_address_const::<0x111111>()
}

fn SIGNED_TX_DATA(guardian_tx: bool) -> SignedTransactionData {
  SignedTransactionData {
    private_key: 1234,
    public_key: 883045738439352841478194533192765345509759306772397516907181243450667673002,
    transaction_hash: 2717105892474786771566982177444710571376803476229898722748888396642649184538,
    r: 3068558690657879390136740086327753007413919701043650133111397282816679110801,
    s: 3355728545224320878895493649495491771252432631648740019139167265522817576501,
    guardian: guardian_tx,
  }
}

fn setup_dispatcher(data: Option<@SignedTransactionData>) -> AccountABIDispatcher {
  // Set the transaction version
  testing::set_version(TRANSACTION_VERSION);

  // Deploy the account contract
  let mut calldata = array![];

  match data {
    Option::Some(tx_data) => {
      // Set the signature and transaction hash
      let signature = array![*tx_data.r, *tx_data.s];

      testing::set_signature(signature.span());
      testing::set_transaction_hash(*tx_data.transaction_hash);

      if (*tx_data.guardian) {
        calldata.append(SIGNER_PUBLIC_KEY);
        calldata.append(*tx_data.public_key);
      } else {
        calldata.append(*tx_data.public_key);
        calldata.append(GUARDIAN_PUBLIC_KEY);
      }
    },
    Option::None(_) => {
      calldata.append(SIGNER_PUBLIC_KEY);
      calldata.append(GUARDIAN_PUBLIC_KEY);
    }
  };

  let address = utils::deploy(Account::TEST_CLASS_HASH, calldata);
  testing::set_account_contract_address(address);

  AccountABIDispatcher { contract_address: address }
}

fn deploy_erc20(recipient: starknet::ContractAddress, initial_supply: u256) -> IERC20Dispatcher {
  let name = 0;
  let symbol = 0;
  let calldata = array![
    name,
    symbol,
    initial_supply.low.into(),
    initial_supply.high.into(),
    recipient.into(),
  ];

  let address = utils::deploy(ERC20::TEST_CLASS_HASH, calldata);
  IERC20Dispatcher { contract_address: address }
}

#[test]
#[available_gas(20000000)]
fn test_constructor() {
  let mut account = Account::contract_state_for_testing();

  account.initializer(signer_public_key_: SIGNER_PUBLIC_KEY, guardian_public_key_: GUARDIAN_PUBLIC_KEY);

  assert(
    account.get_signer_public_key() == SIGNER_PUBLIC_KEY,
    'Should return signer pubkey'
  );
  assert(
    account.get_guardian_public_key() == GUARDIAN_PUBLIC_KEY,
    'Should return guardian pubkey'
  );
}

#[test]
#[available_gas(20000000)]
fn test_interfaces() {
  let mut account = Account::contract_state_for_testing();

  account.initializer(signer_public_key_: SIGNER_PUBLIC_KEY, guardian_public_key_: GUARDIAN_PUBLIC_KEY);

  assert(account.supports_interface(ISRC5_ID), 'Should support base interface');
  assert(account.supports_interface(ISRC6_ID), 'Should support account id');
}

#[test]
#[available_gas(20000000)]
fn test_is_valid_signature() {
  let mut account = Account::contract_state_for_testing();

  let data = SIGNED_TX_DATA(guardian_tx: false);
  let message = data.transaction_hash;

  let good_signature = array![data.r, data.s];
  let bad_signature = array![0x987, 0x564];

  account.set_signer_public_key(data.public_key);

  // Test good signature
  let is_valid = account.is_valid_signature(message, good_signature);
  assert(is_valid == starknet::VALIDATED, 'Should accept valid signature');

  // Test bad signature
  let is_valid = account.is_valid_signature(message, bad_signature);
  assert(is_valid == 0, 'Should reject invalid signature');
}

#[test]
#[available_gas(20000000)]
fn test_validate_deploy() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  // `__validate_deploy__` does not directly use the passed arguments. Their
  // values are already integrated in the tx hash. The passed arguments in this
  // testing context are decoupled from the signature and have no effect on the test.
  assert(
    account.__validate_deploy__(CLASS_HASH(), SALT, SIGNER_PUBLIC_KEY, GUARDIAN_PUBLIC_KEY) == starknet::VALIDATED,
    'Should validate correctly'
  );
}

#[test]
#[available_gas(20000000)]
fn test_validate_deploy_invalid_signature_data() {
  let mut data = SIGNED_TX_DATA(guardian_tx: false);
  data.transaction_hash += 1;
  let account = setup_dispatcher(Option::Some(@data));

  account.__validate_deploy__(CLASS_HASH(), SALT, SIGNER_PUBLIC_KEY, GUARDIAN_PUBLIC_KEY);
}

#[test]
#[available_gas(20000000)]
fn test_validate_deploy_invalid_signature_length() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));
  let signature = array![0x1];

  testing::set_signature(signature.span());

  account.__validate_deploy__(CLASS_HASH(), SALT, SIGNER_PUBLIC_KEY, GUARDIAN_PUBLIC_KEY);
}

#[test]
#[available_gas(20000000)]
fn test_validate_deploy_empty_signature() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));
  let empty_sig = array![];

  testing::set_signature(empty_sig.span());
  account.__validate_deploy__(CLASS_HASH(), SALT, SIGNER_PUBLIC_KEY, GUARDIAN_PUBLIC_KEY);
}

#[test]
#[available_gas(20000000)]
fn test_validate_declare() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  // `__validate_declare__` does not directly use the class_hash argument. Its
  // value is already integrated in the tx hash. The class_hash argument in this
  // testing context is decoupled from the signature and has no effect on the test.
  assert(
    account.__validate_declare__(CLASS_HASH()) == starknet::VALIDATED,
    'Should validate correctly'
  );
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_declare_invalid_signature_data() {
  let mut data = SIGNED_TX_DATA(guardian_tx: false);
  data.transaction_hash += 1;
  let account = setup_dispatcher(Option::Some(@data));

  account.__validate_declare__(CLASS_HASH());
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_declare_invalid_signature_length() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));
  let signature = array![0x1];

  testing::set_signature(signature.span());

  account.__validate_declare__(CLASS_HASH());
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_declare_empty_signature() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));
  let empty_sig = array![];

  testing::set_signature(empty_sig.span());

  account.__validate_declare__(CLASS_HASH());
}

#[test]
#[available_gas(20000000)]
fn test_execute() {
  test_execute_with_version(Option::None(()));
}

#[test]
#[available_gas(20000000)]
fn test_execute_query_version() {
  test_execute_with_version(Option::Some(QUERY_VERSION));
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid tx version', 'ENTRYPOINT_FAILED'))]
fn test_execute_invalid_version() {
  test_execute_with_version(Option::Some(TRANSACTION_VERSION - 1));
}

#[test]
#[available_gas(20000000)]
fn test_validate() {
  let calls = array![];
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  assert(account.__validate__(calls) == starknet::VALIDATED, 'Should validate correctly');
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_validate_invalid() {
  let calls = array![];
  let mut data = SIGNED_TX_DATA(guardian_tx: false);
  data.transaction_hash += 1;
  let account = setup_dispatcher(Option::Some(@data));

  account.__validate__(calls);
}

#[test]
#[available_gas(20000000)]
fn test_multicall() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));
  let erc20 = deploy_erc20(account.contract_address, 1000);
  let recipient1 = starknet::contract_address_const::<0x123>();
  let recipient2 = starknet::contract_address_const::<0x456>();

  // Craft call1
  let amount1: u256 = 300;
  let calldata1 = array![recipient1.into(), amount1.low.into(), amount1.high.into()];

  let call1 = starknet::account::Call {
    to: erc20.contract_address, selector: TRANSFER_SELECTOR, calldata: calldata1
  };

  // Craft call2
  let amount2: u256 = 500;
  let calldata2 = array![recipient2.into(), amount2.low.into(), amount2.high.into()];

  let call2 = starknet::account::Call {
    to: erc20.contract_address, selector: TRANSFER_SELECTOR, calldata: calldata2
  };

  // Bundle calls and exeute
  let calls = array![call1, call2];
  let ret = account.__execute__(calls);

  // Assert that the transfers were successful
  assert(erc20.balance_of(account.contract_address) == 200, 'Should have remainder');
  assert(erc20.balance_of(recipient1) == 300, 'Should have transferred');
  assert(erc20.balance_of(recipient2) == 500, 'Should have transferred');

  // Test return value
  let mut call1_serialized_retval = *ret.at(0);
  let mut call2_serialized_retval = *ret.at(1);
  let call1_retval = Serde::<bool>::deserialize(ref call1_serialized_retval);
  let call2_retval = Serde::<bool>::deserialize(ref call2_serialized_retval);
  assert(call1_retval.unwrap(), 'Should have succeeded');
  assert(call2_retval.unwrap(), 'Should have succeeded');
}

#[test]
#[available_gas(20000000)]
fn test_multicall_zero_calls() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));
  let calls = array![];

  let ret = account.__execute__(calls);

  // Test return value
  assert(ret.len() == 0, 'Should have an empty response');
}

#[test]
#[available_gas(20000000)]
fn test_public_key_setter_and_getter() {
  let mut account = Account::contract_state_for_testing();

  testing::set_contract_address(ACCOUNT_ADDRESS());
  testing::set_caller_address(ACCOUNT_ADDRESS());

  account.set_signer_public_key(NEW_SIGNER_PUBKEY);
  account.set_guardian_public_key(NEW_GUARDIAN_PUBKEY);

  assert(account.get_signer_public_key() == NEW_SIGNER_PUBKEY, 'Should update signer key');
  assert(account.get_guardian_public_key() == NEW_GUARDIAN_PUBKEY, 'Should update guardian key');
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: unauthorized', ))]
fn test_signer_public_key_setter_different_account() {
  let mut account = Account::contract_state_for_testing();

  let caller = starknet::contract_address_const::<0x123>();
  testing::set_contract_address(ACCOUNT_ADDRESS());
  testing::set_caller_address(caller);

  account.set_signer_public_key(NEW_SIGNER_PUBKEY);
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: unauthorized', ))]
fn test_guardian_public_key_setter_different_account() {
  let mut account = Account::contract_state_for_testing();

  let caller = starknet::contract_address_const::<0x123>();
  testing::set_contract_address(ACCOUNT_ADDRESS());
  testing::set_caller_address(caller);

  account.set_guardian_public_key(NEW_GUARDIAN_PUBKEY);
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: no reentrant call', ))]
fn test_account_called_from_contract() {
  let mut account = Account::contract_state_for_testing();

  let calls = array![];
  let caller = starknet::contract_address_const::<0x123>();
  testing::set_contract_address(ACCOUNT_ADDRESS());
  testing::set_caller_address(caller);
  account.__execute__(calls);
}

// Escape signature validation

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_trigger_signer_escape_with_signer_signature() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  // Craft calls
  let calls = array![
    starknet::account::Call {
      to: account.contract_address,
      selector: Account::TRIGGER_ESCAPE_SIGNER_SELECTOR,
      calldata: array![],
    },
  ];

  account.__validate__(calls);
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid signature', 'ENTRYPOINT_FAILED'))]
fn test_escape_signer_with_signer_signature() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  // Craft calls
  let calls = array![
    starknet::account::Call {
      to: account.contract_address,
      selector: Account::ESCAPE_SIGNER_SELECTOR,
      calldata: array![],
    },
  ];

  account.__validate__(calls);
}

#[test]
#[available_gas(20000000)]
fn test_trigger_signer_escape_with_guardian_signature() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: true)));

  // Craft calls
  let calls = array![
    starknet::account::Call {
      to: account.contract_address,
      selector: Account::TRIGGER_ESCAPE_SIGNER_SELECTOR,
      calldata: array![],
    },
  ];

  account.__validate__(calls);
}

#[test]
#[available_gas(20000000)]
fn test_escape_signer_with_guardian_signature() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: true)));

  // Craft calls
  let calls = array![
    starknet::account::Call {
      to: account.contract_address,
      selector: Account::ESCAPE_SIGNER_SELECTOR,
      calldata: array![],
    },
  ];

  account.__validate__(calls);
}

// Trigger signer escape

#[test]
#[available_gas(20000000)]
fn test_trigger_signer_escape() {
  let mut account = Account::contract_state_for_testing();

  assert(account.get_signer_escape_activation_date().is_zero(), 'escape activation date before');

  testing::set_block_timestamp(BLOCK_TIMESTAMP());
  account.trigger_signer_escape();

  assert(
    account.get_signer_escape_activation_date() == BLOCK_TIMESTAMP() + Account::ESCAPE_SECURITY_PERIOD,
    'escape activation date after'
  );
}

#[test]
#[available_gas(20000000)]
fn test_multiple_trigger_signer_escape() {
  let mut account = Account::contract_state_for_testing();

  assert(account.get_signer_escape_activation_date().is_zero(), 'escape activation date before');

  testing::set_block_timestamp(1_u64);
  account.trigger_signer_escape();

  assert(
    account.get_signer_escape_activation_date() == 1_u64 + Account::ESCAPE_SECURITY_PERIOD,
    'escape activation date after'
  );

  testing::set_block_timestamp(BLOCK_TIMESTAMP());
  account.trigger_signer_escape();

  assert(
    account.get_signer_escape_activation_date() == BLOCK_TIMESTAMP() + Account::ESCAPE_SECURITY_PERIOD,
    'escape activation date after'
  );
}

// Cancel escape

#[test]
#[available_gas(20000000)]
fn test_cancel_escape() {
  let mut account = Account::contract_state_for_testing();

  assert(account.get_signer_escape_activation_date().is_zero(), 'escape activation date before');

  testing::set_block_timestamp(BLOCK_TIMESTAMP());
  account.trigger_signer_escape();

  account.cancel_escape();

  assert(account.get_signer_escape_activation_date().is_zero(), 'escape activation date after');
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: no escape to cancel', ))]
fn test_cancel_escape_nonexistant() {
  let mut account = Account::contract_state_for_testing();

  account.cancel_escape();
}

// Escape signer

#[test]
#[available_gas(20000000)]
fn test_escape_signer() {
  let mut account = Account::contract_state_for_testing();

  testing::set_block_timestamp(BLOCK_TIMESTAMP());
  account.trigger_signer_escape();

  testing::set_block_timestamp(BLOCK_TIMESTAMP() + Account::ESCAPE_SECURITY_PERIOD);
  account.escape_signer(NEW_SIGNER_PUBKEY);

  assert(account.get_signer_escape_activation_date().is_zero(), 'escape activation date after');
  assert(account.get_signer_public_key() == NEW_SIGNER_PUBKEY, 'signer public key after');
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: no escape', ))]
fn test_escape_signer_without_triggering_signer_escape() {
  let mut account = Account::contract_state_for_testing();

  account.escape_signer(NEW_SIGNER_PUBKEY);
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid escape', ))]
fn test_escape_signer_before_activation_date() {
  let mut account = Account::contract_state_for_testing();

  testing::set_block_timestamp(BLOCK_TIMESTAMP());
  account.trigger_signer_escape();

  testing::set_block_timestamp(BLOCK_TIMESTAMP() + Account::ESCAPE_SECURITY_PERIOD - 1);
  account.escape_signer(NEW_SIGNER_PUBKEY);
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: new pk cannot be null', ))]
fn test_escape_signer_with_zero() {
  let mut account = Account::contract_state_for_testing();

  testing::set_block_timestamp(BLOCK_TIMESTAMP());
  account.trigger_signer_escape();

  testing::set_block_timestamp(BLOCK_TIMESTAMP() + Account::ESCAPE_SECURITY_PERIOD);
  account.escape_signer(0);
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: unauthorized', 'ENTRYPOINT_FAILED'))]
fn test_upgrade_unauthorized() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  assert(!account.supports_interface(0xdead), 'interface support before');

  account.upgrade(new_implementation: ValidUpgrade::TEST_CLASS_HASH.try_into().unwrap());

  assert(account.supports_interface(0xdead), 'interface support after');
}

// replace syscall in test mode not available yet

// #[test]
// #[available_gas(20000000)]
// fn test_upgrade_valid_implementation() {
//   let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

//   let calldata = array![ValidUpgrade::TEST_CLASS_HASH]

//   let calls = array![
//     starknet::account::Call {
//       to: account.contract_address,
//       selector: UPGRADE_SELECTOR,
//       calldata,
//     },
//   ];

//   assert(!account.supports_interface(0xdead), 'interface support before');

//   account.__execute__(:calls);

//   assert(account.supports_interface(0xdead), 'interface support after');
// }

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: invalid implementation', 'ENTRYPOINT_FAILED', 'ENTRYPOINT_FAILED'))]
fn test_upgrade_invalid_implementation() {
  let account = setup_dispatcher(Option::Some(@SIGNED_TX_DATA(guardian_tx: false)));

  let calldata = array![InvalidUpgrade::TEST_CLASS_HASH];

  let calls = array![
    starknet::account::Call {
      to: account.contract_address,
      selector: UPGRADE_SELECTOR,
      calldata,
    },
  ];

  account.__execute__(:calls);
}

//
// Test internals
//

#[test]
#[available_gas(20000000)]
fn test_initializer() {
  let mut account = Account::contract_state_for_testing();

  account.initializer(SIGNER_PUBLIC_KEY, GUARDIAN_PUBLIC_KEY);
  assert(account.get_signer_public_key() == SIGNER_PUBLIC_KEY, 'Should return signer pubkey');
  assert(account.get_guardian_public_key() == GUARDIAN_PUBLIC_KEY, 'Should return guardian pubkey');
}

#[test]
#[available_gas(20000000)]
fn test_assert_only_self_true() {
  let mut account = Account::contract_state_for_testing();

  testing::set_contract_address(ACCOUNT_ADDRESS());
  testing::set_caller_address(ACCOUNT_ADDRESS());
  account._only_self();
}

#[test]
#[available_gas(20000000)]
#[should_panic(expected: ('Account: unauthorized', ))]
fn test_assert_only_self_false() {
  let mut account = Account::contract_state_for_testing();

  testing::set_contract_address(ACCOUNT_ADDRESS());
  let other = starknet::contract_address_const::<0x4567>();
  testing::set_caller_address(other);
  account._only_self();
}

#[test]
#[available_gas(20000000)]
fn test__is_valid_signature() {
  let mut account = Account::contract_state_for_testing();

  let data = SIGNED_TX_DATA(guardian_tx: false);
  let message = data.transaction_hash;

  let good_signature = array![data.r, data.s];

  let bad_signature = array![0x987, 0x564];

  let invalid_length_signature = array![0x987];

  account.set_signer_public_key(data.public_key);

  let is_valid = account._is_valid_signature(message, good_signature.span(), data.public_key);
  assert(is_valid, 'Should accept valid signature');

  let is_valid = account._is_valid_signature(message, bad_signature.span(), data.public_key);
  assert(!is_valid, 'Should reject invalid signature');

  let is_valid = account._is_valid_signature(message, invalid_length_signature.span(), data.public_key);
  assert(!is_valid, 'Should reject invalid length');
}

//
// Internals
//

fn test_execute_with_version(version: Option<felt252>) {
  let data = SIGNED_TX_DATA(guardian_tx: false);
  let account = setup_dispatcher(Option::Some(@data));
  let erc20 = deploy_erc20(account.contract_address, 1000);
  let recipient = starknet::contract_address_const::<0x123>();

  // Craft call and add to calls array
  let amount: u256 = 200;
  let calldata = array![recipient.into(), amount.low.into(), amount.high.into()];

  let calls = array![
    starknet::account::Call {
      to: erc20.contract_address,
      selector: TRANSFER_SELECTOR,
      calldata,
    },
  ];

  // Handle version for test
  if version.is_some() {
    testing::set_version(version.unwrap());
  }

  // Execute
  let ret = account.__execute__(calls);

  // Assert that the transfer was successful
  assert(erc20.balance_of(account.contract_address) == 800, 'Should have remainder');
  assert(erc20.balance_of(recipient) == amount, 'Should have transferred');

  // Test return value
  let mut call_serialized_retval = *ret.at(0);
  let call_retval = Serde::<bool>::deserialize(ref call_serialized_retval);
  assert(call_retval.unwrap(), 'Should have succeeded');
}
