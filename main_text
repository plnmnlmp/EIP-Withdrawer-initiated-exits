### Withdrawer initiated exits

##Abstract
Introduce a new type of message from a dedicated smart contract to trigger a validator exit. The message provides the owner of type 0x01 withdrawal credentials the capability to initiate the validator exit.

##Motivation
Currently, control over withdrawal credentials doesn’t provide the capability to initiate the validator exit and withdraw the funds. This goes against the needs and intuitive rights of stake owners, and creates difficulties for delegated staking solutions. The methods used to circumvent these problems - such as presigned voluntary exit requests - are cumbersome to implement safely or trustlessly. Thus it seems important that withdrawer exits get enabled in the Ethereum protocol.


##Solution
We propose to use a similar mechanism as is used for deposits to initiate the exits by 0x01 withdrawal credentials. To make sure the beacon chain is not DoSed by exit requests, we propose to implement a set of validity checks on the execution layer (using Merkle proofs vs beacon state root) and set a limit to the number of valid exit attempts per block. If all validity checks are passed, a message is emitted on EL as an EVM event from a smart contract. Then parsed, and processed on a beacon chain client just like DepositEvent from DepositContract is processed.
One difference from a deposit contract is that we propose this event to be a request from the execution layer to consensus layer that is not guaranteed to succeed. The reason for this is that making this request a guaranteed success would require a tighter coupling between execution layer and consensus layer that seems healthy.

##Specification 
The sequence of operations for triggering a withdrawal is divided into two parts: first, pre-checks implemented in the smart contract and emission of an event, and then the event processing on the beacon chain client.

#Exit initiation smart contract

The dedicated contract sequentially checks four conditions:
1. The last exit request from this validator was at least WITHDRAWER_EXIT_ATTEMPTS_INTERVAL blocks ago.
2. The number of successful executions of the function for the current block does not exceed the limitation (MAX_EXIT_REQUESTS_PER_BLOCK).
3. The msg.sender address corresponds to the specified validator’s withdrawal credentials.
4. The validator is active and mature enough to initiate an exit: the time elapsed since activation exceeds SHARD_COMMITTEE_PERIOD epochs (which is 256 epochs ~ 27 hours for now).



##Pseudocode

#A contract:
```solidity
interface IExitContract {
    event ExitRequestMessageEvent(Message message);
        bytes pubkey,
        bytes withdrawal_credentials
    );

    function doWithdrawalRequest(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        uint256 current_epoch, 
        uint256 validator_activation_epoch, 
        uint256 validator_exit_epoch  
    );
    function get_exits_hash() external view returns (bytes32);
    function get_exit_counter() external view returns (bytes memory);
}

contract ExitContract is IExitContract {
    
    uint constant MAX_EXIT_NUMBER = 16;                     #TBD
    uint constant WITHDRAWER_EXIT_ATTEMPTS_INTERVAL = 1024; #TBD
   
    mapping(bytes => uint256) private attemptedAt;       # validator’s pubkey => block number
    
    bytes32[MAX_EXIT_NUMBER] exits;

    uint256 exits_counter;
    uint64 exits_hash; #TODO можно не сохранять 
    
    uint256 currentBN;

    #Zeroing counter, clear an array and a hash of concatenated exits
    function flush() {
        exits_counter = 0;    
        for (uint i = 0; i < MAX_EXIT_NUMBER; i++)
            exits[i] = 0;
        exits_hash = 0; 
    }

    constructor() public {
        flush();
    }


  struct WithdrawerExitRequest {
    address withdrawerAddress;
        bytes pubkey;
        bytes32[MAX_EXIT_NUMBER] exits;
        uint256 exits_counter;    #TODO?
        uint64 exits_hash;        #TODO
  }


    function get_exits_hash() {
         return to_little_endian_64(uint64(exits_hash));
    }

    function get_count() {
        return to_little_endian_64(uint64(exits_counter));
    }

    function doWithdrawalRequest(
        bytes calldata pubkey,
        bytes calldata withdrawal_credentials,
        bytes calldata signature,
        uint256 current_epoch, 
        uint256 validator_activation_epoch, 
        uint256 validator_exit_epoch  
    ) public {
        uint256 bN = block.number;
    if (currentBN != bN) {
            currentBN = bN;
            flush();
        }

        require(
      bN - attemptedAt[pubkey] > WITHDRAWER_EXIT_ATTEMPTS_INTERVAL,
      "Too frequent exit attempts for this validator"
      );
        if (current_epoch < validator_activation_epoch + SHARD_COMMITTEE_PERIOD) { revert("The validator is too young")} #TODO not defined

    if (current_epoch >= validator_exit_epoch) { revert("The validator is not active anymore")}

        require(exits_counter < MAX_EXIT_NUMBER, "Too many withdrawal attempts within the block");

        # Since everything is ok, lets add an information to all stores and emit a message
        
        exits_counter++;
        attemptedAt[pubkey] = bN;
        
        exits[exits_counter - 1] = ; #TODO
        
        #calculating a hash of all accumulated exits TODO

        if (exits_counter > 0) {
            exits_hash = sha256(abi.encodePacked(exits[0 : exits_counter - 1]));
        }
        
        WithdrawerExitRequest memory withdrawerExitRequest = WithdrawerExitRequest(msg.sender, pubkey, exits, exits_counter, exits_hash); #TODO
    bytes memory encodedData = abi.encode(withdrawerExitRequest);
    
    emit Message(encodedData); #TODO
        assert(false);
    }

    #TODO return hash and amount?
    function getWithdrawerExitRequestData -> (hash, count?)


function to_little_endian_64(uint64 value) internal pure returns (bytes memory ret) {
        ret = new bytes(8);
        bytes8 bytesValue = bytes8(value);
        // Byteswapping during copying to bytes.
        ret[0] = bytesValue[7];
        ret[1] = bytesValue[6];
        ret[2] = bytesValue[5];
        ret[3] = bytesValue[4];
        ret[4] = bytesValue[3];
        ret[5] = bytesValue[2];
        ret[6] = bytesValue[1];
        ret[7] = bytesValue[0];
    }
}

```
