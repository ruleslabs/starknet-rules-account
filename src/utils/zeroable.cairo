// Not available in cairo@1.1.0 but coming soon
impl U64Zeroable of Zeroable<u64> {
  fn zero() -> u64 {
    0
  }
  #[inline(always)]
  fn is_zero(self: u64) -> bool {
    self == U64Zeroable::zero()
  }
  #[inline(always)]
  fn is_non_zero(self: u64) -> bool {
    self != U64Zeroable::zero()
  }
}
