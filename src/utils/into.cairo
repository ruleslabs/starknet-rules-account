impl BoolIntoU8 of Into<bool, u8> {
  #[inline(always)]
  fn into(self: bool) -> u8 {
    if (self) {
      1_u8
    } else {
      0_u8
    }
  }
}
