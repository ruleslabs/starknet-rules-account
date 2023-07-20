#[starknet::contract]
mod ValidUpgrade {
  #[storage]
  struct Storage { }

  #[constructor]
  fn constructor(ref self: ContractState) {}

  #[external(v0)]
  fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
    true
  }
}

#[starknet::contract]
mod InvalidUpgrade {
  #[storage]
  struct Storage { }

  #[constructor]
  fn constructor(ref self: ContractState) {}

  #[external(v0)]
  fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
    false
  }
}
