# Withdrawer initiated exits

## Abstract
Introduce a new type of message from a dedicated smart contract to trigger a validator exit. The message provides the owner of type 0x01 withdrawal credentials the capability to initiate the validator exit.

## Motivation
Currently, control over withdrawal credentials doesn’t provide the capability to initiate the validator exit and withdraw the funds. This goes against the needs and intuitive rights of stake owners, and creates difficulties for delegated staking solutions. The methods used to circumvent these problems - such as presigned voluntary exit requests - are cumbersome to implement safely or trustlessly. Thus it seems important that withdrawer exits get enabled in the Ethereum protocol.


## Solution
We propose to use a similar mechanism as is used for deposits to initiate the exits by 0x01 withdrawal credentials. To make sure the beacon chain is not DoSed by exit requests, we propose to implement a set of validity checks on the execution layer and set a limit to the number of valid exit attempts per block. If all validity checks are passed, a message is emitted on EL as an EVM event from a smart contract. Then the request is parsed and processed on a beacon chain client just like DepositEvent from DepositContract is processed.
One difference from a deposit contract is that we propose this event to be a request from the execution layer to consensus layer that is not guaranteed to succeed. The reason for this is that making this request a guaranteed success would require a tighter coupling between execution layer and consensus layer that seems healthy.
The other difference is the following. Just like events from deposit contract, withdrawer initiated exit requests' events need to be validatable even in the absence of access to execution layer blocks' data, e.g. in case Ethereum implements EIP-XXXX many years from now. That means that consensus layer needs to store some data to authenticate the validity of requests. Unlike deposit messages, exit requests themselves do not need a permanent append-only data structure, so we defaulted to putting a hash of all of relevant blocks' (#TODO - which block is it? 8h ago?) exit requests messages to the blocks' eth1_data. The array of exit requests and `exit_requests_hash` can be cleared for each new block. The goal is to give a possibility for future verification of all logged exit requests without access to the execution layer data: "enough validators back in the day signed that data".

## Specification
The sequence of operations for triggering a withdrawal is divided into two parts: first, pre-checks implemented in the smart contract and emission of an event, and then the event processing on the beacon chain client.

### Exit initiation smart contract
The dedicated contract sequentially checks the following conditions:
1. The last exit request from this validator was at least `WITHDRAWER_EXIT_ATTEMPTS_INTERVAL` blocks ago.
2. The number of successful executions of the function for the current block does not exceed the limitation (`MAX_EXIT_REQUESTS_PER_BLOCK`).
3. The msg.sender address corresponds to the specified validator’s withdrawal credentials.
4. The validator is active and mature enough to initiate an exit: the time elapsed since activation exceeds `SHARD_COMMITTEE_PERIOD` epochs (which is 256 epochs ~ 27 hours for now).

If all conditions are fulfilled, the contract emits an event `WithdrawerExitRequest`, stores an information about a new exit attempt in an array and this array's hash, and updates a state variables.

### Processing an event
When the consensus layer client has received an event `WithdrawerExitRequest`, first of all it checks if the current block is not overloaded by exit attempts. If it is not - the client checks the state of a validator named in a request to make sure that it is not already exited, is active, and the withdrawal credentials match the withdrawerAddress. We propose to do the double check on the consensus side in case there’s a bug in the smart contract or on the execution layer as a whole or requirements on the consensus layer will change with the upgrade (see the “Other considerations” section below).
If these conditions are fulfilled, the client verifies that the received event message is confirmed by consensus over eth1_data.
And then, if everything is fine with a message, the exit is triggered.

Withdrawer request initiator shouldn’t assume the request will definitely be successfully processed by the beacon chain. It’s possible it will fail and smart contract systems using this EIP should be designed with this assumption in mind.

## Pseudocode

### A contract:
```solidity
pragma solidity ^0.8.0;

interface IExitContract {
    event ExitRequestMessageEvent(
        bytes pubkey,
        bytes withdrawal_credentials,
        bytes encoded_data
    );

    function doExitRequest(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        uint256 current_epoch,
        uint256 validator_activation_epoch,
        uint256 validator_exit_epoch
    ) external;

    function getWithdrawerExitRequestsHash() external view returns (bytes32);
    function getWithdrawerExitRequestsCounter() external view returns (uint256);
}

contract ExitContract is IExitContract {

    uint256 constant MAX_EXIT_NUMBER = 16;
    uint256 constant WITHDRAWER_EXIT_ATTEMPTS_INTERVAL = 1024;
    uint256 constant SHARD_COMMITTEE_PERIOD = 256;

    mapping(bytes => uint256) private attempted_at;       // validator’s pubkey => block number

    bytes32[MAX_EXIT_NUMBER] withdrawer_exit_requests;    // successively accumulates hashes of pubkeys and withdrawal credentials for requesting exits
    bytes32 withdrawer_exit_requests_hash;

    uint256 withdrawer_exit_requests_counter;

    uint256 current_block_number;

    constructor() {
        // all contract fields are zeroed by default
    }

    struct WithdrawerExitRequest {
        address withdrawerAddress;
        bytes pubkey;
        bytes32[MAX_EXIT_NUMBER] withdrawer_exit_requests;
        bytes32 withdrawer_exit_requests_hash;
    }

    function getWithdrawerExitRequestsHash() external view override returns (bytes32) {
        return _toLittleEndian(withdrawer_exit_requests_hash);
    }

    function getWithdrawerExitRequestsCounter() external view override returns (uint256) {
        return withdrawer_exit_requests_counter;
    }

    function doExitRequest(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature, //TODO unused ?
        uint256 current_epoch,
        uint256 validator_activation_epoch,
        uint256 validator_exit_epoch
    ) public override {
        uint256 bN = block.number;
        if (current_block_number != bN) {
            current_block_number = bN;
            _flush();
        }

        require(withdrawer_exit_requests_counter < MAX_EXIT_NUMBER, "Too many withdrawal attempts within the block");
        require(bN - attempted_at[pubkey] > WITHDRAWER_EXIT_ATTEMPTS_INTERVAL, "Too frequent exit attempts for this validator");

        if (current_epoch < validator_activation_epoch + SHARD_COMMITTEE_PERIOD) { revert("The validator is too young"); }

        if (current_epoch >= validator_exit_epoch) { revert("The validator is not active anymore"); }

        // Since everything is ok, lets add an information to the array and emit a message

        withdrawer_exit_requests_counter++;
        attempted_at[pubkey] = bN;

        withdrawer_exit_requests[withdrawer_exit_requests_counter - 1] = keccak256(abi.encodePacked(pubkey, withdrawal_credentials)); // or maybe just a pubkey? and no need to do keccak256?

        bytes memory encoded;
        for (uint i = 0; i < withdrawer_exit_requests_counter; i++) {
            encoded = bytes.concat(encoded, abi.encodePacked(withdrawer_exit_requests[i]));
        }
        withdrawer_exit_requests_hash = keccak256(encoded);

        WithdrawerExitRequest memory withdrawerExitRequest = WithdrawerExitRequest(msg.sender, pubkey, withdrawer_exit_requests, withdrawer_exit_requests_hash); //TODO
        bytes memory encodedData = abi.encode(withdrawerExitRequest);

        emit ExitRequestMessageEvent(pubkey, withdrawal_credentials, encodedData); //TODO
        assert(false); //TODO ???
    }

    //TODO return hash and amount?
    function getWithdrawerExitRequestData() external view returns (bytes memory) {
        return abi.encodePacked(withdrawer_exit_requests_hash, withdrawer_exit_requests_counter);
    }

    // Zeroing counter, clear an array and a hash of concatenated exits
    function _flush() internal {
        withdrawer_exit_requests_counter = 0;
        for (uint i = 0; i < MAX_EXIT_NUMBER; i++)
            withdrawer_exit_requests[i] = 0;
        withdrawer_exit_requests_hash = 0;
    }

    function _toLittleEndian(bytes32 value) internal pure returns (bytes32) {
        uint256 ret = uint256(value);

        // https://graphics.stanford.edu/~seander/bithacks.html#ReverseParallel

        // swap bytes
        ret = ((ret & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8) |
            ((ret & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);

        // swap 2-byte long pairs
        ret = ((ret & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16) |
            ((ret & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);

        // swap 4-byte long pairs
        ret = ((ret & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32) |
            ((ret & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);

        // swap 8-byte long pairs
        ret = ((ret & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64) |
            ((ret & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);

        // swap 16-byte long pairs
        ret = (ret >> 128) | (ret << 128);

        return bytes32(ret);
    }
}

```

### An extension of the Beacon spec:
```python
class WithdrawerExitRequestData(Container):
    pubkey: BLSPubkey
    withdrawal_credentials: Bytes32

class BeaconBlockBody(Container):
    #...
    withdrawer_exit_requests: List[WithdrawerExitRequestData, MAX_EXIT_NUMBER]

def process_block(state: BeaconState, block: BeaconBlock) -> None:  #nothing new here: copied from https://github.com/ethereum/consensus-specs/blob/v0.12.0/specs/phase0/beacon-chain.md
    process_block_header(state, block)
    process_randao(state, block.body)
    process_eth1_data(state, block.body)
    process_operations(state, block.body)

#TODO
def process_eth1_data(state, body):
    ...
    assert eth1_data.withdrawer_exit_requests_hash = keccak256(abi.encodePacked((body.withdrawer_exit_requests[:])))
    ...


def process_operations(state: BeaconState, body: BeaconBlockBody) -> None:

    ...
    assert len(body.withdrawer_exit_requests) == state.eth1_data.withdrawer_exit_requests_counter	# Just delete this?

    assert is_valid_hash(state.eth1_data.withdrawer_exit_requests, state.eth1_data.withdrawer_exit_requests_hash);

    def for_ops(operations: Sequence[Any], fn: Callable[[BeaconState, Any], None]) -> None:
        for operation in operations:
            fn(state, operation)

    for_ops(body.proposer_slashings, process_proposer_slashing)
    for_ops(body.attester_slashings, process_attester_slashing)
    for_ops(body.attestations, process_attestation)
    for_ops(body.deposits, process_deposit)
    for_ops(body.voluntary_withdrawer_exit_requests, process_voluntary_exit)

    #todo - assume authencity checked
    for_ops(body.withdrawer_exit_requests, process_withdrawer_exit_requests) #TODO


def is_withdrawer_exit_valid(state: BeaconState, withdrawer_exit: WithdrawerExitRequest) -> bool:
    validator = state.validators[withdrawer_exit.validator_index]

    # Verify the validator is active
    if not is_active_validator(validator, get_current_epoch(state)):
        return false;

    # Verify exit has not been initiated
    if not validator.exit_epoch == FAR_FUTURE_EPOCH:
        return false

    # Verify the validator has been active long enough
    if not get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD:
        return false

    # Check withdrawer_exit was indeed initiated by withdrawal credentials
    # return withdrawer_exit.withdrawer_address == validator.withdrawal_credentials


def is_valid_hash(listtocheck: Sequence[Bytes32], hashsum: uint64) -> bool:
    uint64 count = len(listtocheck)
    calculatedhash = 0
    if count > 0:
        calculatedhash = keccak256(abi.encodePacked(listtocheck[0 : count - 1]));    # !!! need to make this consistent with what is calculated on the EL
    return calculatedhash == hashsum


def process_withdrawer_exit_request(state: BeaconState, withdrawer_exit: WithdrawerExitRequest) -> None:

    if is_withdrawer_exit_valid(state, withdrawer_exit):
        initiate_validator_exit(state, withdrawer_exit.validator_index)

def process_withdrawer_exit_requests(state: BeaconState,
               withdrawer_exit_request: WithdrawerExitRequest) -> None:
    withdrawer_exit = withdrawer_exit_request.message
    validator = state.validators[withdrawer_exit_request.validator_pubkey]


    assert is_active_validator(validator, get_current_epoch(state))
    assert validator.exit_epoch == FAR_FUTURE_EPOCH
    assert get_current_epoch(state) >= withdrawer_exit.epoch
    assert get_current_epoch(state) >= validator.activation_epoch + SHARD_COMMITTEE_PERIOD

    #verify hash?
```

### A client-side pseudocode:
```solidity
func (vs *Server) withdrawer_deposits(
  ctx context.Context,
  beaconState state.BeaconState,
  currentVote *ethpb.Eth1Data,
) ([]*ethpb.Deposit, error) {
  # ...

  var pendingExits []*ethpb.WithdrawerExitContainer
  for i, exit := range allPendingContainers {

  # check of exit request validity as it's described in Beacon
# spec is_withdrawer_exit_valid, where isExitValid function
# does the check
    if isExitValid(exit) {
      pendingExits = append(pendingExits, exit)
    }

    // Don't do more than the max allowed amount of checks
    if i == params.BeaconConfig().MaxWithdrawerExitsChecksPerBlock {
        break
    }

# Don't try to pack more than the max allowed in a block
    if uint64(len(pendingExits)) == params.BeaconConfig().MaxWithdrawerExitsPerBlock {
      break
    }

  }
  # ...
}
```

## External dependencies
The procedure requires direct access to the Beacon state root. Therefore, there is a dependency on the [EIP‑4788](https://eips.ethereum.org/EIPS/eip-4788). Note that this design is compatible with validator index reuse if Ethereum ever wants to implement that.

## Backwards Compatibility
This EIP can make the solutions that rely on the validator key owner to be able to hold funds hostage from withdrawal credential owners obsolete. We didn’t find anyone who relies on this assumption in practice, but in theory there could be entities like this..

## Security Considerations
The main security issue is a threat of DoS attack on Consensus Layer. The proposing procedure includes the simple protection mechanisms against attacks of this type:
1. The withdrawal requests from each individual validator cannot be sent very often.
2. The total number of withdrawal requests per block is limited.

Since the counter of withdrawal attempts for a block is only incremented in a case of a valid request, it is not possible to exhaust the per‑block limit with multiple cheap invalid attempts. A valid attempt to do an exit request on the execution layer is not easy to spam: you can only do it once per validator.

## Other considerations
1. There are several elements in the proposed design that need to be discussed separately.
This EIP introduces a second data pipe from the execution layer to the consensus layer after the deposit contract. Given that the coupling is designed in much the same way as deposit contract is, it shouldn’t increase the complexity of consensus clients significantly, as the same code could be reused. Nevertheless, it’s an increase in complexity.
2. Validity of the request on consensus layer is checked using consensus layer constants. These constants are not necessarily immutable between upgrades. In the code for the execution layer we can only rely on the smart contract defined constants. In case the consensus layer constants change with future upgrades, the execution layer code can start producing invalid exit requests. There's two ways to treat that problem: one is for apps to consider an execution layer request to be a failable one and design itself accordingly; and the other is to get a way to get CL constants to EL. The design above chooses the former option.
In the proposed design, it is decided to limit the minimum interval between two exit requests from the same validator. An alternative design would be based on the convention that each validator has a right for exactly one correct request. This option is more optimal in terms of computational complexity. The corresponding unoptimised code could be like below:

```solidity
mapping(uint256 => bool) private attempted_at;	     // validator id => attempted
.....
require(!attempted_at[validatorID], "This validator is already exited");
.....
attempted_at[validatorID] = true;
```

3. Note that the validator index is used here as an index, not the public key. So, this design depends on validator ids not being reused. Though this dependency is easy to reconsider if needed.
The arguments in favor of the boolean flags option are as follows:
In an optimized version, boolean flags can be stored in a bitmap. This gives a significant performance gain.
Problems in query execution on the consensus layer side are extremely unlikely.
It’s a lot easier to build systems on top of this contract when exit requests go through without
The main argument in favor of chosen design is that the limit on the number of requests accepted on the beacon side can be changed (a constant `MAX_VOLUNTARY_EXITS`). So it is possible that the contract will fire an exit request message which will be rejected at the consensus layer. But the flag for the validator that sent the request will already be switched, which means that the future attempts will no longer be possible.

4. Existing protocols provide a limitation for the possibility of voluntary exits. The number of such exits within one block is limited by the `MAX_VOLUNTARY_EXITS` constant, [which is currently 16](https://github.com/ethereum/consensus-specs/blob/dev/specs/phase0/beacon-chain.md#max-operations-per-block). This EIP proposes to create another source of exit requests. It is difficult to predict in advance how often this function will be used, and how many already existing voluntary withdrawals it will replace. In the pseudocode above, the constant limiting the number of exit messages per block is also equal to 16, for a total maximum number of initiated exits per slot increasing to 32. But the question of what this value should be needs to be discussed.
