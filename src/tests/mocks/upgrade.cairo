#[account_contract]
mod ValidUpgrade {
  #[constructor]
  fn constructor() {}

  #[view]
  fn supports_interface(interface_id: u32) -> bool {
    true
  }
}

#[account_contract]
mod InvalidUpgrade {
  #[constructor]
  fn constructor() {}

  #[view]
  fn supports_interface(interface_id: u32) -> bool {
    false
  }
}
