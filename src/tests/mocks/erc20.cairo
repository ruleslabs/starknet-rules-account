#[starknet::interface]
trait IERC20<TContractState> {
  fn name(self: @TContractState) -> felt252;

  fn symbol(self: @TContractState) -> felt252;

  fn decimals(self: @TContractState) -> u8;

  fn total_supply(self: @TContractState) -> u256;

  fn balance_of(self: @TContractState, account: starknet::ContractAddress) -> u256;

  fn allowance(self: @TContractState, owner: starknet::ContractAddress, spender: starknet::ContractAddress) -> u256;

  fn transfer(ref self: TContractState, recipient: starknet::ContractAddress, amount: u256) -> bool;

  fn transfer_from(
    ref self: TContractState,
    sender: starknet::ContractAddress,
    recipient: starknet::ContractAddress,
    amount: u256
  ) -> bool;

  fn approve(ref self: TContractState, spender: starknet::ContractAddress, amount: u256) -> bool;

  fn increase_allowance(ref self: TContractState, spender: starknet::ContractAddress, added_value: u256) -> bool;

  fn decrease_allowance(ref self: TContractState, spender: starknet::ContractAddress, subtracted_value: u256) -> bool;
}

#[starknet::contract]
mod ERC20 {
  use super::IERC20;
  use integer::BoundedInt;
  use zeroable::Zeroable;

  #[storage]
  struct Storage {
    _name: felt252,
    _symbol: felt252,
    _total_supply: u256,
    _balances: LegacyMap<starknet::ContractAddress, u256>,
    _allowances: LegacyMap<(starknet::ContractAddress, starknet::ContractAddress), u256>,
  }

  //
  // Constructor
  //

  #[constructor]
  fn constructor(
    ref self: ContractState,
    name_: felt252,
    symbol_: felt252,
    initial_supply: u256,
    recipient: starknet::ContractAddress
  ) {
    self.initializer(:name_, :symbol_, :initial_supply, :recipient);
  }

  #[external(v0)]
  impl ERC20 of IERC20<ContractState> {
    fn name(self: @ContractState) -> felt252 {
      self._name.read()
    }

    fn symbol(self: @ContractState) -> felt252 {
      self._symbol.read()
    }

    fn decimals(self: @ContractState) -> u8 {
      18_u8
    }

    fn total_supply(self: @ContractState) -> u256 {
      self._total_supply.read()
    }

    fn balance_of(self: @ContractState, account: starknet::ContractAddress) -> u256 {
      self._balances.read(account)
    }

    fn allowance(self: @ContractState, owner: starknet::ContractAddress, spender: starknet::ContractAddress) -> u256 {
      self._allowances.read((owner, spender))
    }

    fn transfer(ref self: ContractState, recipient: starknet::ContractAddress, amount: u256) -> bool {
      let sender = starknet::get_caller_address();
      self._transfer(sender, recipient, amount);
      true
    }

    fn transfer_from(
      ref self: ContractState,
      sender: starknet::ContractAddress,
      recipient: starknet::ContractAddress,
      amount: u256
    ) -> bool {
      let caller = starknet::get_caller_address();
      self._spend_allowance(sender, caller, amount);
      self._transfer(sender, recipient, amount);
      true
    }

    fn approve(ref self: ContractState, spender: starknet::ContractAddress, amount: u256) -> bool {
      let caller = starknet::get_caller_address();
      self._approve(caller, spender, amount);
      true
    }

    fn increase_allowance(ref self: ContractState, spender: starknet::ContractAddress, added_value: u256) -> bool {
      self._increase_allowance(spender, added_value)
    }

    fn decrease_allowance(ref self: ContractState, spender: starknet::ContractAddress, subtracted_value: u256) -> bool {
      self._decrease_allowance(spender, subtracted_value)
    }
  }

  //
  // Internals
  //

  #[generate_trait]
  impl InternalImpl of InternalTrait {
    fn initializer(
    ref self: ContractState,
    name_: felt252,
    symbol_: felt252,
    initial_supply: u256,
    recipient: starknet::ContractAddress
  ) {
      self._name.write(name_);
      self._symbol.write(symbol_);

      self._mint(recipient, initial_supply);
    }

    fn _increase_allowance(ref self: ContractState, spender: starknet::ContractAddress, added_value: u256) -> bool {
      let caller = starknet::get_caller_address();
      self._approve(caller, spender, self._allowances.read((caller, spender)) + added_value);
      true
    }

    fn _decrease_allowance(
      ref self: ContractState,
      spender: starknet::ContractAddress,
      subtracted_value: u256
    ) -> bool {
      let caller = starknet::get_caller_address();
      self._approve(caller, spender, self._allowances.read((caller, spender)) - subtracted_value);
      true
    }

    fn _mint(ref self: ContractState, recipient: starknet::ContractAddress, amount: u256) {
      assert(!recipient.is_zero(), 'ERC20: mint to 0');
      self._total_supply.write(self._total_supply.read() + amount);
      self._balances.write(recipient, self._balances.read(recipient) + amount);
    }

    fn _burn(ref self: ContractState, account: starknet::ContractAddress, amount: u256) {
      assert(!account.is_zero(), 'ERC20: burn from 0');
      self._total_supply.write(self._total_supply.read() - amount);
      self._balances.write(account, self._balances.read(account) - amount);
    }

    fn _approve(
      ref self: ContractState,
      owner: starknet::ContractAddress, spender: starknet::ContractAddress, amount: u256) {
      assert(!owner.is_zero(), 'ERC20: approve from 0');
      assert(!spender.is_zero(), 'ERC20: approve to 0');
      self._allowances.write((owner, spender), amount);
    }

    fn _transfer(
      ref self: ContractState,
      sender: starknet::ContractAddress,
      recipient: starknet::ContractAddress,
      amount: u256
    ) {
      assert(!sender.is_zero(), 'ERC20: transfer from 0');
      assert(!recipient.is_zero(), 'ERC20: transfer to 0');
      self._balances.write(sender, self._balances.read(sender) - amount);
      self._balances.write(recipient, self._balances.read(recipient) + amount);
    }

    fn _spend_allowance(
      ref self: ContractState,
      owner: starknet::ContractAddress,
      spender: starknet::ContractAddress,
      amount: u256
    ) {
      let current_allowance = self._allowances.read((owner, spender));
      if current_allowance != BoundedInt::max() {
        self._approve(owner, spender, current_allowance - amount);
      }
    }
  }
}
