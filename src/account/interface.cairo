use array::ArrayTrait;
use array::SpanTrait;
use starknet::ContractAddress;

const IACCOUNT_ID: u32 = 0xa66bd575_u32;
const ERC1271_VALIDATED: u32 = 0x1626ba7e_u32;

#[derive(Serde, Drop)]
struct Call {
  to: ContractAddress,
  selector: felt252,
  calldata: Array<felt252>
}
