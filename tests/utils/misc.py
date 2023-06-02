import os

from pathlib import Path
from typing import Optional, List

from starkware.starknet.testing.contract import StarknetContract
from starkware.starknet.compiler.compile import compile_starknet_files
from starkware.starkware_utils.error_handling import StarkException
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from starkware.starknet.business_logic.execution.objects import Event, TransactionExecutionInfo
from starkware.starknet.compiler.compile import get_selector_from_name
from starkware.starknet.business_logic.state.state import BlockInfo
from starkware.starknet.testing.state import StarknetState


DEFAULT_TIMESTAMP = 1640991600


def _get_path_from_name(name):
  """Return the contract path by contract name."""

  for (dirpath, _, filenames) in os.walk('src'):
    for file in filenames:
      if file == f"{name}.cairo":
        return os.path.join(dirpath, file)

  raise FileNotFoundError(f"Cannot find '{name}'.")


def get_contract_class(contract_name):
  path = _get_path_from_name(contract_name)

  contract_class = compile_starknet_files(files=[path], debug_info=True, cairo_path=['src'])
  return contract_class


def str_to_felt(text):
  b_text = bytes(text, 'UTF-8')
  return int.from_bytes(b_text, "big")


def uint(a):
  return a, 0

# TX ASSERTIONS

async def assert_revert(expression, expected_message=None, expected_code=None):
  if expected_code is None:
    expected_code = StarknetErrorCode.TRANSACTION_FAILED
  try:
    await expression
    assert False
  except StarkException as err:
    _, error = err.args
    assert error['code'] == expected_code
    if expected_message is not None:
      assert expected_message in error['message']


def assert_event_emmited(
  tx_exec_info: TransactionExecutionInfo,
  from_address: int,
  name: str,
  data: Optional[List[int]] = []
):
  if not data:
    raw_events = [Event(from_address=event.from_address, keys=event.keys, data=[]) for event in tx_exec_info.get_sorted_events()]
  else:
    raw_events = [Event(from_address=event.from_address, keys=event.keys, data=event.data) for event in tx_exec_info.get_sorted_events()]

  assert Event(from_address=from_address, keys=[get_selector_from_name(name)], data=data) in raw_events

# DEPLOY / DECLARE

async def deploy(starknet, contract_name, params=[]):
  contract_class = get_contract_class(contract_name)
  deployed_contract = await starknet.deploy(contract_class=contract_class, constructor_calldata=params)

  return deployed_contract


async def declare(starknet, contract_name):
  contract_class = get_contract_class(contract_name)
  declared_class = await starknet.declare(contract_class=contract_class)

  return declared_class


async def deploy_proxy(starknet, implementation_contract_name, params=[]):
  implementation_class = await declare(starknet, implementation_contract_name)

  params = [implementation_class.class_hash, get_selector_from_name('initialize'), len(params)] + params

  proxy_class = get_contract_class('Proxy')
  deployed_proxy = await starknet.deploy(contract_class=proxy_class, constructor_calldata=params)

  wrapped_proxy = StarknetContract(
    state=starknet.state,
    abi=implementation_class.abi,
    contract_address=deployed_proxy.contract_address,
    deploy_call_info=deployed_proxy.deploy_call_info
  )
  return deployed_proxy, wrapped_proxy, implementation_class

# BLOCK MGMT

def update_starknet_block(state: StarknetState, block_number=1, block_timestamp=DEFAULT_TIMESTAMP):
  state.state.block_info = BlockInfo(
    block_number=block_number,
    block_timestamp=block_timestamp,
    gas_price=0,
    starknet_version="0.9.1",
    sequencer_address=state.state.block_info.sequencer_address
  )


def reset_starknet_block(state: StarknetState):
  update_starknet_block(state=state)
