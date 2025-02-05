pragma solidity 0.5.17;
pragma experimental ABIEncoderV2;

contract GovernorAlpha {

    /// @notice The name of this contract

    string public constant name = "GAMER Governor Alpha";



    /// @notice The number of votes in support of a proposal required in order for a quorum to be reached and for a vote to succeed

    function quorumVotes() public view returns (uint256) { return SafeMath.div(SafeMath.mul(gamer.initSupply(), 4), 100); } // 4% of GAMER



    /// @notice The number of votes required in order for a voter to become a proposer

    function proposalThreshold() public view returns (uint256) { return SafeMath.div(gamer.initSupply(), 100); } // 1% of GAMER



    /// @notice The maximum number of actions that can be included in a proposal

    function proposalMaxOperations() public pure returns (uint256) { return 10; } // 10 actions



    /// @notice The delay before voting on a proposal may take place, once proposed

    function votingDelay() public pure returns (uint256) { return 1; } // 1 block



    /// @notice The duration of voting on a proposal, in blocks

    function votingPeriod() public pure returns (uint256) { return 17280; } // ~3 days in blocks (assuming 15s blocks)



    /// @notice The address of the Compound Protocol Timelock

    TimelockInterface public timelock;



    /// @notice The address of the Compound governance token

    GAMERInterface public gamer;



    /// @notice The address of the Governor Guardian

    address public guardian;



    /// @notice The total number of proposals

    uint256 public proposalCount;



    struct Proposal {

        /// @notice Unique id for looking up a proposal

        uint256 id;



        /// @notice Creator of the proposal

        address proposer;



        /// @notice The timestamp that the proposal will be available for execution, set once the vote succeeds

        uint256 eta;



        /// @notice the ordered list of target addresses for calls to be made

        address[] targets;



        /// @notice The ordered list of values (i.e. msg.value) to be passed to the calls to be made

        uint[] values;



        /// @notice The ordered list of function signatures to be called

        string[] signatures;



        /// @notice The ordered list of calldata to be passed to each call

        bytes[] calldatas;



        /// @notice The block at which voting begins: holders must delegate their votes prior to this block

        uint256 startBlock;



        /// @notice The block at which voting ends: votes must be cast prior to this block

        uint256 endBlock;



        /// @notice Current number of votes in favor of this proposal

        uint256 forVotes;



        /// @notice Current number of votes in opposition to this proposal

        uint256 againstVotes;



        /// @notice Flag marking whether the proposal has been canceled

        bool canceled;



        /// @notice Flag marking whether the proposal has been executed

        bool executed;



        /// @notice Receipts of ballots for the entire set of voters

        mapping (address => Receipt) receipts;

    }



    /// @notice Ballot receipt record for a voter

    struct Receipt {

        /// @notice Whether or not a vote has been cast

        bool hasVoted;



        /// @notice Whether or not the voter supports the proposal

        bool support;



        /// @notice The number of votes the voter had, which were cast

        uint256 votes;

    }



    /// @notice Possible states that a proposal may be in

    enum ProposalState {

        Pending,

        Active,

        Canceled,

        Defeated,

        Succeeded,

        Queued,

        Expired,

        Executed

    }



    /// @notice The official record of all proposals ever proposed

    mapping (uint256 => Proposal) public proposals;



    /// @notice The latest proposal for each proposer

    mapping (address => uint256) public latestProposalIds;



    /// @notice The EIP-712 typehash for the contract's domain

    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");



    /// @notice The EIP-712 typehash for the ballot struct used by the contract

    bytes32 public constant BALLOT_TYPEHASH = keccak256("Ballot(uint256 proposalId,bool support)");



    /// @notice An event emitted when a new proposal is created

    event ProposalCreated(uint256 id, address proposer, address[] targets, uint[] values, string[] signatures, bytes[] calldatas, uint256 startBlock, uint256 endBlock, string description);



    /// @notice An event emitted when a vote has been cast on a proposal

    event VoteCast(address voter, uint256 proposalId, bool support, uint256 votes);



    /// @notice An event emitted when a proposal has been canceled

    event ProposalCanceled(uint256 id);



    /// @notice An event emitted when a proposal has been queued in the Timelock

    event ProposalQueued(uint256 id, uint256 eta);



    /// @notice An event emitted when a proposal has been executed in the Timelock

    event ProposalExecuted(uint256 id);



    constructor(address timelock_, address gamer_) public {

        timelock = TimelockInterface(timelock_);

        gamer = GAMERInterface(gamer_);

        guardian = msg.sender;

    }



    function propose(

        address[] memory targets,

        uint[] memory values,

        string[] memory signatures,

        bytes[] memory calldatas,

        string memory description

    )

        public

        returns (uint256)

    {

        require(gamer.getPriorVotes(msg.sender, sub256(block.number, 1)) > proposalThreshold(), "GovernorAlpha::propose: proposer votes below proposal threshold");

        require(targets.length == values.length && targets.length == signatures.length && targets.length == calldatas.length, "GovernorAlpha::propose: proposal function information arity mismatch");

        require(targets.length != 0, "GovernorAlpha::propose: must provide actions");

        require(targets.length <= proposalMaxOperations(), "GovernorAlpha::propose: too many actions");



        uint256 latestProposalId = latestProposalIds[msg.sender];

        if (latestProposalId != 0) {

          ProposalState proposersLatestProposalState = state(latestProposalId);

          require(proposersLatestProposalState != ProposalState.Active, "GovernorAlpha::propose: one live proposal per proposer, found an already active proposal");

          require(proposersLatestProposalState != ProposalState.Pending, "GovernorAlpha::propose: one live proposal per proposer, found an already pending proposal");

        }



        uint256 startBlock = add256(block.number, votingDelay());

        uint256 endBlock = add256(startBlock, votingPeriod());



        proposalCount++;

        Proposal memory newProposal = Proposal({

            id: proposalCount,

            proposer: msg.sender,

            eta: 0,

            targets: targets,

            values: values,

            signatures: signatures,

            calldatas: calldatas,

            startBlock: startBlock,

            endBlock: endBlock,

            forVotes: 0,

            againstVotes: 0,

            canceled: false,

            executed: false

        });



        proposals[newProposal.id] = newProposal;

        latestProposalIds[newProposal.proposer] = newProposal.id;



        emit ProposalCreated(

            newProposal.id,

            msg.sender,

            targets,

            values,

            signatures,

            calldatas,

            startBlock,

            endBlock,

            description

        );

        return newProposal.id;

    }



    function queue(uint256 proposalId)

        public

    {

        require(state(proposalId) == ProposalState.Succeeded, "GovernorAlpha::queue: proposal can only be queued if it is succeeded");

        Proposal storage proposal = proposals[proposalId];

        uint256 eta = add256(block.timestamp, timelock.delay());

        for (uint256 i = 0; i < proposal.targets.length; i++) {

            _queueOrRevert(

                proposal.targets[i],

                proposal.values[i],

                proposal.signatures[i],

                proposal.calldatas[i],

                eta

            );

        }

        proposal.eta = eta;

        emit ProposalQueued(proposalId, eta);

    }



    function _queueOrRevert(

        address target,

        uint256 value,

        string memory signature,

        bytes memory data,

        uint256 eta

    )

        internal

    {

        require(!timelock.queuedTransactions(

              keccak256(

                  abi.encode(

                      target,

                      value,

                      signature,

                      data,

                      eta

                  )

              )

          ),

          "GovernorAlpha::_queueOrRevert: proposal action already queued at eta"

        );



        timelock.queueTransaction(target, value, signature, data, eta);

    }



    function execute(uint256 proposalId)

        public

        payable

    {

        require(state(proposalId) == ProposalState.Queued, "GovernorAlpha::execute: proposal can only be executed if it is queued");

        Proposal storage proposal = proposals[proposalId];

        proposal.executed = true;

        for (uint256 i = 0; i < proposal.targets.length; i++) {

            timelock.executeTransaction.value(proposal.values[i])(proposal.targets[i], proposal.values[i], proposal.signatures[i], proposal.calldatas[i], proposal.eta);

        }

        emit ProposalExecuted(proposalId);

    }



    function cancel(uint256 proposalId)

        public

    {

        ProposalState state = state(proposalId);

        require(state != ProposalState.Executed, "GovernorAlpha::cancel: cannot cancel executed proposal");



        Proposal storage proposal = proposals[proposalId];

        require(msg.sender == guardian || gamer.getPriorVotes(proposal.proposer, sub256(block.number, 1)) < proposalThreshold(), "GovernorAlpha::cancel: proposer above threshold");



        proposal.canceled = true;

        for (uint256 i = 0; i < proposal.targets.length; i++) {

            timelock.cancelTransaction(proposal.targets[i], proposal.values[i], proposal.signatures[i], proposal.calldatas[i], proposal.eta);

        }



        emit ProposalCanceled(proposalId);

    }



    function getActions(uint256 proposalId)

        public

        view

        returns (

            address[] memory targets,

            uint[] memory values,

            string[] memory signatures,

            bytes[] memory calldatas

        )

    {

        Proposal storage p = proposals[proposalId];

        return (p.targets, p.values, p.signatures, p.calldatas);

    }



    function getReceipt(uint256 proposalId, address voter)

        public

        view

        returns (Receipt memory)

    {

        return proposals[proposalId].receipts[voter];

    }



    function state(uint256 proposalId)

        public

        view

        returns (ProposalState)

    {

        require(proposalCount >= proposalId && proposalId > 0, "GovernorAlpha::state: invalid proposal id");

        Proposal storage proposal = proposals[proposalId];

        if (proposal.canceled) {

            return ProposalState.Canceled;

        } else if (block.number <= proposal.startBlock) {

            return ProposalState.Pending;

        } else if (block.number <= proposal.endBlock) {

            return ProposalState.Active;

        } else if (proposal.forVotes <= proposal.againstVotes || proposal.forVotes < quorumVotes()) {

            return ProposalState.Defeated;

        } else if (proposal.eta == 0) {

            return ProposalState.Succeeded;

        } else if (proposal.executed) {

            return ProposalState.Executed;

        } else if (block.timestamp >= add256(proposal.eta, timelock.GRACE_PERIOD())) {

            return ProposalState.Expired;

        } else {

            return ProposalState.Queued;

        }

    }



    function castVote(uint256 proposalId, bool support)

        public

    {

        return _castVote(msg.sender, proposalId, support);

    }



    function castVoteBySig(

        uint256 proposalId,

        bool support,

        uint8 v,

        bytes32 r,

        bytes32 s

    )

        public

    {

        bytes32 domainSeparator = keccak256(

            abi.encode(

                DOMAIN_TYPEHASH,

                keccak256(bytes(name)),

                getChainId(),

                address(this)

            )

        );



        bytes32 structHash = keccak256(

            abi.encode(

                BALLOT_TYPEHASH,

                proposalId,

                support

            )

        );



        bytes32 digest = keccak256(

            abi.encodePacked(

                "\x19\x01",

                domainSeparator,

                structHash

            )

        );



        address signatory = ecrecover(digest, v, r, s);

        require(signatory != address(0), "GovernorAlpha::castVoteBySig: invalid signature");

        return _castVote(signatory, proposalId, support);

    }



    function _castVote(

        address voter,

        uint256 proposalId,

        bool support

    )

        internal

    {

        require(state(proposalId) == ProposalState.Active, "GovernorAlpha::_castVote: voting is closed");

        Proposal storage proposal = proposals[proposalId];

        Receipt storage receipt = proposal.receipts[voter];

        require(receipt.hasVoted == false, "GovernorAlpha::_castVote: voter already voted");

        uint256 votes = gamer.getPriorVotes(voter, proposal.startBlock);



        if (support) {

            proposal.forVotes = add256(proposal.forVotes, votes);

        } else {

            proposal.againstVotes = add256(proposal.againstVotes, votes);

        }



        receipt.hasVoted = true;

        receipt.support = support;

        receipt.votes = votes;



        emit VoteCast(voter, proposalId, support, votes);

    }



    function __acceptAdmin()

        public

    {

        require(msg.sender == guardian, "GovernorAlpha::__acceptAdmin: sender must be gov guardian");

        timelock.acceptAdmin();

    }



    function __abdicate()

        public

    {

        require(msg.sender == guardian, "GovernorAlpha::__abdicate: sender must be gov guardian");

        guardian = address(0);

    }



    function __queueSetTimelockPendingAdmin(

        address newPendingAdmin,

        uint256 eta

    )

        public

    {

        require(msg.sender == guardian, "GovernorAlpha::__queueSetTimelockPendingAdmin: sender must be gov guardian");

        timelock.queueTransaction(address(timelock), 0, "setPendingAdmin(address)", abi.encode(newPendingAdmin), eta);

    }



    function __executeSetTimelockPendingAdmin(

        address newPendingAdmin,

        uint256 eta

    )

        public

    {

        require(msg.sender == guardian, "GovernorAlpha::__executeSetTimelockPendingAdmin: sender must be gov guardian");

        timelock.executeTransaction(address(timelock), 0, "setPendingAdmin(address)", abi.encode(newPendingAdmin), eta);

    }



    function add256(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a, "addition overflow");

        return c;

    }



    function sub256(uint256 a, uint256 b) internal pure returns (uint256) {

        require(b <= a, "subtraction underflow");

        return a - b;

    }



    function getChainId() internal pure returns (uint256) {

        uint256 chainId;

        assembly { chainId := chainid() }

        return chainId;

    }

}

interface TimelockInterface {

    function delay() external view returns (uint256);

    function GRACE_PERIOD() external view returns (uint256);

    function acceptAdmin() external;

    function queuedTransactions(bytes32 hash) external view returns (bool);

    function queueTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta) external returns (bytes32);

    function cancelTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta) external;

    function executeTransaction(address target, uint256 value, string calldata signature, bytes calldata data, uint256 eta) external payable returns (bytes memory);

}

interface GAMERInterface {

    function getPriorVotes(address account, uint256 blockNumber) external view returns (uint256);

    function initSupply() external view returns (uint256);

    function _acceptGov() external;

}

contract Timelock {

    using SafeMath for uint256;



    /// @notice An event emitted when the timelock admin changes

    event NewAdmin(address indexed newAdmin);

    /// @notice An event emitted when a new admin is staged in the timelock

    event NewPendingAdmin(address indexed newPendingAdmin);

    event NewDelay(uint indexed newDelay);

    /// @notice An event emitted when a queued transaction is cancelled

    event CancelTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature,  bytes data, uint256 eta);

    /// @notice An event emitted when a queued transaction is executed

    event ExecuteTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature,  bytes data, uint256 eta);

    /// @notice An event emitted when a new transaction is queued

    event QueueTransaction(bytes32 indexed txHash, address indexed target, uint256 value, string signature, bytes data, uint256 eta);



    /// @notice the length of time after the delay has passed that a transaction can be executed

    uint256 public constant GRACE_PERIOD = 14 days;

    /// @notice the minimum length of the timelock delay

    uint256 public constant MINIMUM_DELAY = 2 days; // have to be present for 2 rebases

    /// @notice the maximum length of the timelock delay

    uint256 public constant MAXIMUM_DELAY = 30 days;



    address public admin;

    address public pendingAdmin;

    uint256 public delay;

    bool public admin_initialized;



    mapping (bytes32 => bool) public queuedTransactions;





    constructor()

        public

    {

        /* require(delay_ >= MINIMUM_DELAY, "Timelock::constructor: Delay must exceed minimum delay.");

        require(delay_ <= MAXIMUM_DELAY, "Timelock::setDelay: Delay must not exceed maximum delay."); */



        admin = msg.sender;

        delay = MINIMUM_DELAY;

        admin_initialized = false;

    }



    function() external payable { }





    /**

    @notice sets the delay

    @param delay_ the new delay

     */

    function setDelay(uint256 delay_)

        public

    {

        require(msg.sender == address(this), "Timelock::setDelay: Call must come from Timelock.");

        require(delay_ >= MINIMUM_DELAY, "Timelock::setDelay: Delay must exceed minimum delay.");

        require(delay_ <= MAXIMUM_DELAY, "Timelock::setDelay: Delay must not exceed maximum delay.");

        delay = delay_;



        emit NewDelay(delay);

    }





    /// @notice sets the new admin address

    function acceptAdmin()

        public

    {

        require(msg.sender == pendingAdmin, "Timelock::acceptAdmin: Call must come from pendingAdmin.");

        admin = msg.sender;

        pendingAdmin = address(0);



        emit NewAdmin(admin);

    }



    /**

    @notice queues a new pendingAdmin

    @param pendingAdmin_ the new pendingAdmin address

     */

    function setPendingAdmin(address pendingAdmin_)

        public

    {

        // allows one time setting of admin for deployment purposes

        if (admin_initialized) {

          require(msg.sender == address(this), "Timelock::setPendingAdmin: Call must come from Timelock.");

        } else {

          admin_initialized = true;

        }

        pendingAdmin = pendingAdmin_;



        emit NewPendingAdmin(pendingAdmin);

    }





    function queueTransaction(

        address target,

        uint256 value,

        string memory signature,

        bytes memory data,

        uint256 eta

    )

        public

        returns (bytes32)

    {

        require(msg.sender == admin, "Timelock::queueTransaction: Call must come from admin.");

        require(eta >= getBlockTimestamp().add(delay), "Timelock::queueTransaction: Estimated execution block must satisfy delay.");



        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));

        queuedTransactions[txHash] = true;



        emit QueueTransaction(txHash, target, value, signature, data, eta);

        return txHash;

    }



    function cancelTransaction(

        address target,

        uint256 value,

        string memory signature,

        bytes memory data,

        uint256 eta

    )

        public

    {

        require(msg.sender == admin, "Timelock::cancelTransaction: Call must come from admin.");



        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));

        queuedTransactions[txHash] = false;



        emit CancelTransaction(txHash, target, value, signature, data, eta);

    }



    function executeTransaction(

        address target,

        uint256 value,

        string memory signature,

        bytes memory data,

        uint256 eta

    )

        public

        payable

        returns (bytes memory)

    {

        require(msg.sender == admin, "Timelock::executeTransaction: Call must come from admin.");



        // timelock not enforced prior to updating the admin. This should occur on

        // deployment.

        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));

        if (admin_initialized) {

          require(queuedTransactions[txHash], "Timelock::executeTransaction: Transaction hasn't been queued.");

          require(getBlockTimestamp() >= eta, "Timelock::executeTransaction: Transaction hasn't surpassed time lock.");

          require(getBlockTimestamp() <= eta.add(GRACE_PERIOD), "Timelock::executeTransaction: Transaction is stale.");



          queuedTransactions[txHash] = false;

        }





        bytes memory callData;



        if (bytes(signature).length == 0) {

            callData = data;

        } else {

            callData = abi.encodePacked(bytes4(keccak256(bytes(signature))), data);

        }



        // solium-disable-next-line security/no-call-value

        (bool success, bytes memory returnData) = target.call.value(value)(callData);

        require(success, "Timelock::executeTransaction: Transaction execution reverted.");



        emit ExecuteTransaction(txHash, target, value, signature, data, eta);



        return returnData;

    }



    function getBlockTimestamp() internal view returns (uint256) {

        // solium-disable-next-line security/no-block-members

        return block.timestamp;

    }

}

library Address {

    /**

     * @dev Returns true if `account` is a contract.

     *

     * [IMPORTANT]

     * ====

     * It is unsafe to assume that an address for which this function returns

     * false is an externally-owned account (EOA) and not a contract.

     *

     * Among others, `isContract` will return false for the following

     * types of addresses:

     *

     *  - an externally-owned account

     *  - a contract in construction

     *  - an address where a contract will be created

     *  - an address where a contract lived, but was destroyed

     * ====

     */

    function isContract(address account) internal view returns (bool) {

        // This method relies in extcodesize, which returns 0 for contracts in

        // construction, since the code is only stored at the end of the

        // constructor execution.



        uint256 size;

        // solhint-disable-next-line no-inline-assembly

        assembly { size := extcodesize(account) }

        return size > 0;

    }



    /**

     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to

     * `recipient`, forwarding all available gas and reverting on errors.

     *

     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost

     * of certain opcodes, possibly making contracts go over the 2300 gas limit

     * imposed by `transfer`, making them unable to receive funds via

     * `transfer`. {sendValue} removes this limitation.

     *

     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].

     *

     * IMPORTANT: because control is transferred to `recipient`, care must be

     * taken to not create reentrancy vulnerabilities. Consider using

     * {ReentrancyGuard} or the

     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].

     */

    function sendValue(address payable recipient, uint256 amount) internal {

        require(address(this).balance >= amount, "Address: insufficient balance");



        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value

        (bool success, ) = recipient.call.value(amount)("");

        require(success, "Address: unable to send value, recipient may have reverted");

    }



    /**

     * @dev Performs a Solidity function call using a low level `call`. A

     * plain`call` is an unsafe replacement for a function call: use this

     * function instead.

     *

     * If `target` reverts with a revert reason, it is bubbled up by this

     * function (like regular Solidity function calls).

     *

     * Returns the raw returned data. To convert to the expected return value,

     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].

     *

     * Requirements:

     *

     * - `target` must be a contract.

     * - calling `target` with `data` must not revert.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data) internal returns (bytes memory) {

      return functionCall(target, data, "Address: low-level call failed");

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with

     * `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {

        return _functionCallWithValue(target, data, 0, errorMessage);

    }



    /**

     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],

     * but also transferring `value` wei to `target`.

     *

     * Requirements:

     *

     * - the calling contract must have an ETH balance of at least `value`.

     * - the called Solidity function must be `payable`.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {

        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");

    }



    /**

     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but

     * with `errorMessage` as a fallback revert reason when `target` reverts.

     *

     * _Available since v3.1._

     */

    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {

        require(address(this).balance >= value, "Address: insufficient balance for call");

        return _functionCallWithValue(target, data, value, errorMessage);

    }



    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {

        require(isContract(target), "Address: call to non-contract");



        // solhint-disable-next-line avoid-low-level-calls

        (bool success, bytes memory returndata) = target.call.value(weiValue)(data);

        if (success) {

            return returndata;

        } else {

            // Look for revert reason and bubble it up if present

            if (returndata.length > 0) {

                // The easiest way to bubble the revert reason is using memory via assembly



                // solhint-disable-next-line no-inline-assembly

                assembly {

                    let returndata_size := mload(returndata)

                    revert(add(32, returndata), returndata_size)

                }

            } else {

                revert(errorMessage);

            }

        }

    }

}

library Babylonian {

    function sqrt(uint y) internal pure returns (uint z) {

        if (y > 3) {

            z = y;

            uint x = y / 2 + 1;

            while (x < z) {

                z = x;

                x = (y / x + x) / 2;

            }

        } else if (y != 0) {

            z = 1;

        }

        // else z = 0

    }

}

library FixedPoint {

    // range: [0, 2**112 - 1]

    // resolution: 1 / 2**112

    struct uq112x112 {

        uint224 _x;

    }



    // range: [0, 2**144 - 1]

    // resolution: 1 / 2**112

    struct uq144x112 {

        uint _x;

    }



    uint8 private constant RESOLUTION = 112;

    uint private constant Q112 = uint(1) << RESOLUTION;

    uint private constant Q224 = Q112 << RESOLUTION;



    // encode a uint112 as a UQ112x112

    function encode(uint112 x) internal pure returns (uq112x112 memory) {

        return uq112x112(uint224(x) << RESOLUTION);

    }



    // encodes a uint144 as a UQ144x112

    function encode144(uint144 x) internal pure returns (uq144x112 memory) {

        return uq144x112(uint256(x) << RESOLUTION);

    }



    // divide a UQ112x112 by a uint112, returning a UQ112x112

    function div(uq112x112 memory self, uint112 x) internal pure returns (uq112x112 memory) {

        require(x != 0, 'FixedPoint: DIV_BY_ZERO');

        return uq112x112(self._x / uint224(x));

    }



    // multiply a UQ112x112 by a uint, returning a UQ144x112

    // reverts on overflow

    function mul(uq112x112 memory self, uint y) internal pure returns (uq144x112 memory) {

        uint z;

        require(y == 0 || (z = uint(self._x) * y) / y == uint(self._x), "FixedPoint: MULTIPLICATION_OVERFLOW");

        return uq144x112(z);

    }



    // returns a UQ112x112 which represents the ratio of the numerator to the denominator

    // equivalent to encode(numerator).div(denominator)

    function fraction(uint112 numerator, uint112 denominator) internal pure returns (uq112x112 memory) {

        require(denominator > 0, "FixedPoint: DIV_BY_ZERO");

        return uq112x112((uint224(numerator) << RESOLUTION) / denominator);

    }



    // decode a UQ112x112 into a uint112 by truncating after the radix point

    function decode(uq112x112 memory self) internal pure returns (uint112) {

        return uint112(self._x >> RESOLUTION);

    }



    // decode a UQ144x112 into a uint144 by truncating after the radix point

    function decode144(uq144x112 memory self) internal pure returns (uint144) {

        return uint144(self._x >> RESOLUTION);

    }



    // take the reciprocal of a UQ112x112

    function reciprocal(uq112x112 memory self) internal pure returns (uq112x112 memory) {

        require(self._x != 0, 'FixedPoint: ZERO_RECIPROCAL');

        return uq112x112(uint224(Q224 / self._x));

    }



    // square root of a UQ112x112

    function sqrt(uq112x112 memory self) internal pure returns (uq112x112 memory) {

        return uq112x112(uint224(Babylonian.sqrt(uint256(self._x)) << 56));

    }

}

interface IERC20 {

    /**

     * @dev Returns the amount of tokens in existence.

     */

    function totalSupply() external view returns (uint256);



    /**

     * @dev Returns the amount of tokens owned by `account`.

     */

    function balanceOf(address account) external view returns (uint256);



    /**

     * @dev Moves `amount` tokens from the caller's account to `recipient`.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transfer(address recipient, uint256 amount) external returns (bool);



    /**

     * @dev Returns the remaining number of tokens that `spender` will be

     * allowed to spend on behalf of `owner` through {transferFrom}. This is

     * zero by default.

     *

     * This value changes when {approve} or {transferFrom} are called.

     */

    function allowance(address owner, address spender) external view returns (uint256);



    /**

     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * IMPORTANT: Beware that changing an allowance with this method brings the risk

     * that someone may use both the old and the new allowance by unfortunate

     * transaction ordering. One possible solution to mitigate this race

     * condition is to first reduce the spender's allowance to 0 and set the

     * desired value afterwards:

     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729

     *

     * Emits an {Approval} event.

     */

    function approve(address spender, uint256 amount) external returns (bool);



    /**

     * @dev Moves `amount` tokens from `sender` to `recipient` using the

     * allowance mechanism. `amount` is then deducted from the caller's

     * allowance.

     *

     * Returns a boolean value indicating whether the operation succeeded.

     *

     * Emits a {Transfer} event.

     */

    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);



    /**

     * @dev Emitted when `value` tokens are moved from one account (`from`) to

     * another (`to`).

     *

     * Note that `value` may be zero.

     */

    event Transfer(address indexed from, address indexed to, uint256 value);



    /**

     * @dev Emitted when the allowance of a `spender` for an `owner` is set by

     * a call to {approve}. `value` is the new allowance.

     */

    event Approval(address indexed owner, address indexed spender, uint256 value);

}

interface UniswapPair {

    event Approval(address indexed owner, address indexed spender, uint value);

    event Transfer(address indexed from, address indexed to, uint value);



    function name() external pure returns (string memory);

    function symbol() external pure returns (string memory);

    function decimals() external pure returns (uint8);

    function totalSupply() external view returns (uint);

    function balanceOf(address owner) external view returns (uint);

    function allowance(address owner, address spender) external view returns (uint);



    function approve(address spender, uint value) external returns (bool);

    function transfer(address to, uint value) external returns (bool);

    function transferFrom(address from, address to, uint value) external returns (bool);



    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function PERMIT_TYPEHASH() external pure returns (bytes32);

    function nonces(address owner) external view returns (uint);



    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;



    event Mint(address indexed sender, uint amount0, uint amount1);

    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);

    event Swap(

        address indexed sender,

        uint amount0In,

        uint amount1In,

        uint amount0Out,

        uint amount1Out,

        address indexed to

    );

    event Sync(uint112 reserve0, uint112 reserve1);



    function MINIMUM_LIQUIDITY() external pure returns (uint);

    function factory() external view returns (address);

    function token0() external view returns (address);

    function token1() external view returns (address);

    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);

    function price0CumulativeLast() external view returns (uint);

    function price1CumulativeLast() external view returns (uint);

    function kLast() external view returns (uint);



    function mint(address to) external returns (uint liquidity);

    function burn(address to) external returns (uint amount0, uint amount1);

    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;

    function skim(address to) external;

    function sync() external;



    function initialize(address, address) external;

}

library SafeERC20 {

    using SafeMath for uint256;

    using Address for address;



    function safeTransfer(IERC20 token, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));

    }



    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {

        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));

    }



    /**

     * @dev Deprecated. This function has issues similar to the ones found in

     * {IERC20-approve}, and its usage is discouraged.

     *

     * Whenever possible, use {safeIncreaseAllowance} and

     * {safeDecreaseAllowance} instead.

     */

    function safeApprove(IERC20 token, address spender, uint256 value) internal {

        // safeApprove should only be called when setting an initial allowance,

        // or when resetting it to zero. To increase and decrease it, use

        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'

        // solhint-disable-next-line max-line-length

        require((value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: approve from non-zero to non-zero allowance"

        );

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));

    }



    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).add(value);

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {

        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");

        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement

     * on the return value: the return value is optional (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     */

    function _callOptionalReturn(IERC20 token, bytes memory data) private {

        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since

        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that

        // the target address contains contract code and also asserts for success in the low-level call.



        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional

            // solhint-disable-next-line max-line-length

            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");

        }

    }

}

library SafeMath {

    /**

     * @dev Returns the addition of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `+` operator.

     *

     * Requirements:

     *

     * - Addition cannot overflow.

     */

    function add(uint256 a, uint256 b) internal pure returns (uint256) {

        uint256 c = a + b;

        require(c >= a, "SafeMath: addition overflow");



        return c;

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {

        return sub(a, b, "SafeMath: subtraction overflow");

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     *

     * - Subtraction cannot overflow.

     */

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b <= a, errorMessage);

        uint256 c = a - b;



        return c;

    }



    /**

     * @dev Returns the multiplication of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `*` operator.

     *

     * Requirements:

     *

     * - Multiplication cannot overflow.

     */

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {

        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the

        // benefit is lost if 'b' is also tested.

        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522

        if (a == 0) {

            return 0;

        }



        uint256 c = a * b;

        require(c / a == b, "SafeMath: multiplication overflow");



        return c;

    }



    /**

     * @dev Returns the integer division of two unsigned integers. Reverts on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b) internal pure returns (uint256) {

        return div(a, b, "SafeMath: division by zero");

    }



    /**

     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on

     * division by zero. The result is rounded towards zero.

     *

     * Counterpart to Solidity's `/` operator. Note: this function uses a

     * `revert` opcode (which leaves remaining gas untouched) while Solidity

     * uses an invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b > 0, errorMessage);

        uint256 c = a / b;

        // assert(a == b * c + a % b); // There is no case in which this doesn't hold



        return c;

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * Reverts when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {

        return mod(a, b, "SafeMath: modulo by zero");

    }



    /**

     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),

     * Reverts with custom message when dividing by zero.

     *

     * Counterpart to Solidity's `%` operator. This function uses a `revert`

     * opcode (which leaves remaining gas untouched) while Solidity uses an

     * invalid opcode to revert (consuming all remaining gas).

     *

     * Requirements:

     *

     * - The divisor cannot be zero.

     */

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {

        require(b != 0, errorMessage);

        return a % b;

    }

}

library UniswapV2OracleLibrary {

    using FixedPoint for *;



    // helper function that returns the current block timestamp within the range of uint32, i.e. [0, 2**32 - 1]

    function currentBlockTimestamp() internal view returns (uint32) {

        return uint32(block.timestamp % 2 ** 32);

    }



    // produces the cumulative price using counterfactuals to save gas and avoid a call to sync.

    function currentCumulativePrices(

        address pair,

        bool isToken0

    ) internal view returns (uint priceCumulative, uint32 blockTimestamp) {

        blockTimestamp = currentBlockTimestamp();

        (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast) = UniswapPair(pair).getReserves();

        if (isToken0) {

          priceCumulative = UniswapPair(pair).price0CumulativeLast();



          // if time has elapsed since the last update on the pair, mock the accumulated price values

          if (blockTimestampLast != blockTimestamp) {

              // subtraction overflow is desired

              uint32 timeElapsed = blockTimestamp - blockTimestampLast;

              // addition overflow is desired

              // counterfactual

              priceCumulative += uint(FixedPoint.fraction(reserve1, reserve0)._x) * timeElapsed;

          }

        } else {

          priceCumulative = UniswapPair(pair).price1CumulativeLast();

          // if time has elapsed since the last update on the pair, mock the accumulated price values

          if (blockTimestampLast != blockTimestamp) {

              // subtraction overflow is desired

              uint32 timeElapsed = blockTimestamp - blockTimestampLast;

              // addition overflow is desired

              // counterfactual

              priceCumulative += uint(FixedPoint.fraction(reserve0, reserve1)._x) * timeElapsed;

          }

        }



    }

}

interface Reserves {

    function distributeTreasuryReward(uint256 amount) external;

}

contract GAMERRebaser {



    using SafeMath for uint256;



    modifier onlyGov() {

        require(msg.sender == gov);

        _;

    }



    struct Transaction {

        bool enabled;

        address destination;

        bytes data;

    }



    struct UniVars {

      uint256 gamersToUni;

      uint256 amountFromReserves;

      uint256 mintToReserves;

    }



    /// @notice an event emitted when a transaction fails

    event TransactionFailed(address indexed destination, uint index, bytes data);



    /// @notice an event emitted when maxSlippageFactor is changed

    event NewMaxSlippageFactor(uint256 oldSlippageFactor, uint256 newSlippageFactor);



    /// @notice an event emitted when deviationThreshold is changed

    event NewDeviationThreshold(uint256 oldDeviationThreshold, uint256 newDeviationThreshold);



    /**

     * @notice Sets the treasury mint percentage of rebase

     */

    event NewRebaseMintPercent(uint256 oldRebaseMintPerc, uint256 newRebaseMintPerc);





    /**

     * @notice Sets the reserve contract

     */

    event NewReserveContract(address oldReserveContract, address newReserveContract);



    /**

     * @notice Sets the treasury reward ratio

     */

    event NewTreasuryRewardRatio(uint256 oldTreasuryRewardRatio, uint256 newTreasuryRewardRatio);



    /**

     * @notice Sets the reserve contract

     */

    event TreasuryIncreased(uint256 reservesAdded, uint256 gamersSold, uint256 gamersFromReserves, uint256 gamersToReserves);





    /**

     * @notice Event emitted when pendingGov is changed

     */

    event NewPendingGov(address oldPendingGov, address newPendingGov);



    /**

     * @notice Event emitted when gov is changed

     */

    event NewGov(address oldGov, address newGov);



    // Stable ordering is not guaranteed.

    Transaction[] public transactions;





    /// @notice Governance address

    address public gov;



    /// @notice Pending Governance address

    address public pendingGov;



    /// @notice Spreads out getting to the target price

    uint256 public rebaseLag;



    /// @notice Peg target

    uint256 public targetRate;



    /// @notice Percent of rebase that goes to minting for treasury building

    uint256 public rebaseMintPerc;



    // If the current exchange rate is within this fractional distance from the target, no supply

    // update is performed. Fixed point number--same format as the rate.

    // (ie) abs(rate - targetRate) / targetRate < deviationThreshold, then no supply change.

    uint256 public deviationThreshold;



    /// @notice More than this much time must pass between rebase operations.

    uint256 public minRebaseTimeIntervalSec;



    /// @notice Block timestamp of last rebase operation

    uint256 public lastRebaseTimestampSec;



    /// @notice The rebase window begins this many seconds into the minRebaseTimeInterval period.

    // For example if minRebaseTimeInterval is 24hrs, it represents the time of day in seconds.

    uint256 public rebaseWindowOffsetSec;



    /// @notice The length of the time window where a rebase operation is allowed to execute, in seconds.

    uint256 public rebaseWindowLengthSec;



    /// @notice The number of rebase cycles since inception

    uint256 public epoch;



    // rebasing is not active initially. It can be activated at T+12 hours from

    // deployment time

    ///@notice boolean showing rebase activation status

    bool public rebasingActive;



    /// @notice delays rebasing activation to facilitate liquidity

    // uint256 public constant rebaseDelay = 24 hours;

    uint256 public constant rebaseDelay = 24 hours;



    /// @notice Time of TWAP initialization

    uint256 public timeOfTWAPInit;



    /// @notice GAMER token address

    address public gamerAddress;



    /// @notice reserve token

    address public reserveToken;



    /// @notice Reserves vault contract

    address public reservesContract;



    /// @notice Reserves treasury reward ratio

    uint256 public treasuryRewardRatio;



    /// @notice pair for reserveToken <> GAMER

    address public uniswap_pair;



    /// @notice last TWAP update time

    uint32 public blockTimestampLast;



    /// @notice last TWAP cumulative price;

    uint256 public priceCumulativeLast;



    // Max slippage factor when buying reserve token. Magic number based on

    // the fact that uniswap is a constant product. Therefore,

    // targeting a % max slippage can be achieved by using a single precomputed

    // number. i.e. 2.5% slippage is always equal to some f(maxSlippageFactor, reserves)

    /// @notice the maximum slippage factor when buying reserve token

    uint256 public maxSlippageFactor;



    /// @notice Whether or not this token is first in uniswap GAMER<>Reserve pair

    bool public isToken0;



    constructor(

        address gamerAddress_,

        address reserveToken_,

        address uniswap_factory,

        address reservesContract_

    )

        public

    {

          minRebaseTimeIntervalSec = 24 hours;

          rebaseWindowOffsetSec = 4 hours; // 4AM UTC rebases

          reservesContract = reservesContract_;

          (address token0, address token1) = sortTokens(gamerAddress_, reserveToken_);



          // used for interacting with uniswap

          if (token0 == gamerAddress_) {

              isToken0 = true;

          } else {

              isToken0 = false;

          }

          // uniswap GAMER<>Reserve pair

          uniswap_pair = pairFor(uniswap_factory, token0, token1);



          // Reserves contract is mutable

          reservesContract = reservesContract_;



          // Reserve token is not mutable. Must deploy a new rebaser to update it

          reserveToken = reserveToken_;



          gamerAddress = gamerAddress_;



          // target 10% slippage

          // 5.4%

          maxSlippageFactor = 5409258 * 10**10;



          // 1 DAI

          targetRate = 10**18;



          // once daily rebase, with targeting reaching peg in 20 days

          rebaseLag = 20;



          // 5%

          rebaseMintPerc = 5 * 10**16;



          // 5%

          deviationThreshold = 5 * 10**16;



          // 60 minutes

          rebaseWindowLengthSec = 60 * 60;



          // 10%

          treasuryRewardRatio = 10**17;



          // Changed in deployment scripts to facilitate protocol initiation

          gov = msg.sender;



    }



    /**

    @notice Updates slippage factor

    @param maxSlippageFactor_ the new slippage factor

    *

    */

    function setMaxSlippageFactor(uint256 maxSlippageFactor_)

        public

        onlyGov

    {

        uint256 oldSlippageFactor = maxSlippageFactor;

        maxSlippageFactor = maxSlippageFactor_;

        emit NewMaxSlippageFactor(oldSlippageFactor, maxSlippageFactor_);

    }



    /**

    @notice Updates rebase mint percentage

    @param rebaseMintPerc_ the new rebase mint percentage

    *

    */

    function setRebaseMintPerc(uint256 rebaseMintPerc_)

        public

        onlyGov

    {

        uint256 oldPerc = rebaseMintPerc;

        rebaseMintPerc = rebaseMintPerc_;

        emit NewRebaseMintPercent(oldPerc, rebaseMintPerc_);

    }





    /**

    @notice Updates reserve contract

    @param reservesContract_ the new reserve contract

    *

    */

    function setReserveContract(address reservesContract_)

        public

        onlyGov

    {

        address oldReservesContract = reservesContract;

        reservesContract = reservesContract_;

        emit NewReserveContract(oldReservesContract, reservesContract_);

    }



    /** @notice sets the pendingGov

     * @param treasuryRewardRatio_ The treasury reward ratio of the treasury pool.

     */

    function setTreasuryRewardRatio(uint256 treasuryRewardRatio_)

        external

        onlyGov

    {

        uint256 oldTreasuryRewardRatio = treasuryRewardRatio;

        treasuryRewardRatio = treasuryRewardRatio_;

        emit NewTreasuryRewardRatio(oldTreasuryRewardRatio, treasuryRewardRatio_);

    }

    

    /** @notice sets the pendingGov

     * @param pendingGov_ The address of the rebaser contract to use for authentication.

     */

    function _setPendingGov(address pendingGov_)

        external

        onlyGov

    {

        address oldPendingGov = pendingGov;

        pendingGov = pendingGov_;

        emit NewPendingGov(oldPendingGov, pendingGov_);

    }



    /** @notice lets msg.sender accept governance

     *

     */

    function _acceptGov()

        external

    {

        require(msg.sender == pendingGov, "!pending");

        address oldGov = gov;

        gov = pendingGov;

        pendingGov = address(0);

        emit NewGov(oldGov, gov);

    }



    /** @notice Initializes TWAP start point, starts countdown to first rebase

    *

    */

    function init_twap()

        public

    {

        require(timeOfTWAPInit == 0, "already activated");

        (uint priceCumulative, uint32 blockTimestamp) =

           UniswapV2OracleLibrary.currentCumulativePrices(uniswap_pair, isToken0);

        require(blockTimestamp > 0, "no trades");

        blockTimestampLast = blockTimestamp;

        priceCumulativeLast = priceCumulative;

        timeOfTWAPInit = blockTimestamp;

    }



    /** @notice Activates rebasing

    *   @dev One way function, cannot be undone, callable by anyone

    */

    function activate_rebasing()

        public

    {

        require(timeOfTWAPInit > 0, "twap wasnt intitiated, call init_twap()");

        // cannot enable prior to end of rebaseDelay

        require(now >= timeOfTWAPInit + rebaseDelay, "!end_delay");



        rebasingActive = true;

    }



    /**

     * @notice Initiates a new rebase operation, provided the minimum time period has elapsed.

     *

     * @dev The supply adjustment equals (_totalSupply * DeviationFromTargetRate) / rebaseLag

     *      Where DeviationFromTargetRate is (MarketOracleRate - targetRate) / targetRate

     *      and targetRate is 1e18

     */

    function rebase()

        public

    {

        // EOA only

        require(msg.sender == tx.origin);

        // ensure rebasing at correct time

        _inRebaseWindow();



        // This comparison also ensures there is no reentrancy.

        require(lastRebaseTimestampSec.add(minRebaseTimeIntervalSec) < now);



        // Snap the rebase time to the start of this window.

        lastRebaseTimestampSec = now.sub(

            now.mod(minRebaseTimeIntervalSec)).add(rebaseWindowOffsetSec);



        epoch = epoch.add(1);



        // get twap from uniswap v2;

        uint256 exchangeRate = getTWAP();



        // calculates % change to supply

        (uint256 offPegPerc, bool positive) = computeOffPegPerc(exchangeRate);



        uint256 indexDelta = offPegPerc;



        // Apply the Dampening factor.

        indexDelta = indexDelta.div(rebaseLag);



        GAMERTokenInterface gamer = GAMERTokenInterface(gamerAddress);



        if (positive) {

            require(gamer.gamersScalingFactor().mul(uint256(10**18).add(indexDelta)).div(10**18) < gamer.maxScalingFactor(), "new scaling factor will be too big");

        }





        uint256 currSupply = gamer.totalSupply();



        uint256 mintAmount;

        // reduce indexDelta to account for minting

        if (positive) {

            uint256 mintPerc = indexDelta.mul(rebaseMintPerc).div(10**18);

            indexDelta = indexDelta.sub(mintPerc);

            mintAmount = currSupply.mul(mintPerc).div(10**18);

        } else if (offPegPerc > uint256(0)) {

            uint256 totalTreasury = IERC20(reserveToken).balanceOf(reservesContract);

            if (totalTreasury > 0 && treasuryRewardRatio > 0) {

                uint256 treasuryReward = totalTreasury.mul(treasuryRewardRatio).div(10**18);

                Reserves(reservesContract).distributeTreasuryReward(treasuryReward);

            }

        }



        // rebase

        uint256 supplyAfterRebase = gamer.rebase(epoch, indexDelta, positive);

        assert(gamer.gamersScalingFactor() <= gamer.maxScalingFactor());



        // perform actions after rebase

        afterRebase(mintAmount, offPegPerc);

    }





    function uniswapV2Call(

        address sender,

        uint256 amount0,

        uint256 amount1,

        bytes memory data

    )

        public

    {

        // enforce that it is coming from uniswap

        require(msg.sender == uniswap_pair, "bad msg.sender");

        // enforce that this contract called uniswap

        require(sender == address(this), "bad origin");

        (UniVars memory uniVars) = abi.decode(data, (UniVars));



        GAMERTokenInterface gamer = GAMERTokenInterface(gamerAddress);



        if (uniVars.amountFromReserves > 0) {

            // transfer from reserves and mint to uniswap

            gamer.transferFrom(reservesContract, uniswap_pair, uniVars.amountFromReserves);

            if (uniVars.amountFromReserves < uniVars.gamersToUni) {

                // if the amount from reserves > gamersToUni, we have fully paid for the DAI tokens

                // thus this number would be 0 so no need to mint

                gamer.mint(uniswap_pair, uniVars.gamersToUni.sub(uniVars.amountFromReserves));

            }

        } else {

            // mint to uniswap

            gamer.mint(uniswap_pair, uniVars.gamersToUni);

        }



        // mint unsold to mintAmount

        if (uniVars.mintToReserves > 0) {

            gamer.mint(reservesContract, uniVars.mintToReserves);

        }



        // transfer reserve token to reserves

        if (isToken0) {

            SafeERC20.safeTransfer(IERC20(reserveToken), reservesContract, amount1);

            emit TreasuryIncreased(amount1, uniVars.gamersToUni, uniVars.amountFromReserves, uniVars.mintToReserves);

        } else {

            SafeERC20.safeTransfer(IERC20(reserveToken), reservesContract, amount0);

            emit TreasuryIncreased(amount0, uniVars.gamersToUni, uniVars.amountFromReserves, uniVars.mintToReserves);

        }

    }



    function buyReserveAndTransfer(

        uint256 mintAmount,

        uint256 offPegPerc

    )

        internal

    {

        UniswapPair pair = UniswapPair(uniswap_pair);



        GAMERTokenInterface gamer = GAMERTokenInterface(gamerAddress);



        // get reserves

        (uint256 token0Reserves, uint256 token1Reserves, ) = pair.getReserves();



        // check if protocol has excess gamer in the reserve

        uint256 excess = gamer.balanceOf(reservesContract);





        uint256 tokens_to_max_slippage = uniswapMaxSlippage(token0Reserves, token1Reserves, offPegPerc);



        UniVars memory uniVars = UniVars({

          gamersToUni: tokens_to_max_slippage, // how many gamers uniswap needs

          amountFromReserves: excess, // how much of gamersToUni comes from reserves

          mintToReserves: 0 // how much gamers protocol mints to reserves

        });



        // tries to sell all mint + excess

        // falls back to selling some of mint and all of excess

        // if all else fails, sells portion of excess

        // upon pair.swap, `uniswapV2Call` is called by the uniswap pair contract

        if (isToken0) {

            if (tokens_to_max_slippage > mintAmount.add(excess)) {

                // we already have performed a safemath check on mintAmount+excess

                // so we dont need to continue using it in this code path



                // can handle selling all of reserves and mint

                uint256 buyTokens = getAmountOut(mintAmount + excess, token0Reserves, token1Reserves);

                uniVars.gamersToUni = mintAmount + excess;

                uniVars.amountFromReserves = excess;

                // call swap using entire mint amount and excess; mint 0 to reserves

                pair.swap(0, buyTokens, address(this), abi.encode(uniVars));

            } else {

                if (tokens_to_max_slippage > excess) {

                    // uniswap can handle entire reserves

                    uint256 buyTokens = getAmountOut(tokens_to_max_slippage, token0Reserves, token1Reserves);



                    // swap up to slippage limit, taking entire gamer reserves, and minting part of total

                    uniVars.mintToReserves = mintAmount.sub((tokens_to_max_slippage - excess));

                    pair.swap(0, buyTokens, address(this), abi.encode(uniVars));

                } else {

                    // uniswap cant handle all of excess

                    uint256 buyTokens = getAmountOut(tokens_to_max_slippage, token0Reserves, token1Reserves);

                    uniVars.amountFromReserves = tokens_to_max_slippage;

                    uniVars.mintToReserves = mintAmount;

                    // swap up to slippage limit, taking excess - remainingExcess from reserves, and minting full amount

                    // to reserves

                    pair.swap(0, buyTokens, address(this), abi.encode(uniVars));

                }

            }

        } else {

            if (tokens_to_max_slippage > mintAmount.add(excess)) {

                // can handle all of reserves and mint

                uint256 buyTokens = getAmountOut(mintAmount + excess, token1Reserves, token0Reserves);

                uniVars.gamersToUni = mintAmount + excess;

                uniVars.amountFromReserves = excess;

                // call swap using entire mint amount and excess; mint 0 to reserves

                pair.swap(buyTokens, 0, address(this), abi.encode(uniVars));

            } else {

                if (tokens_to_max_slippage > excess) {

                    // uniswap can handle entire reserves

                    uint256 buyTokens = getAmountOut(tokens_to_max_slippage, token1Reserves, token0Reserves);



                    // swap up to slippage limit, taking entire gamer reserves, and minting part of total

                    uniVars.mintToReserves = mintAmount.sub((tokens_to_max_slippage - excess));

                    // swap up to slippage limit, taking entire gamer reserves, and minting part of total

                    pair.swap(buyTokens, 0, address(this), abi.encode(uniVars));

                } else {

                    // uniswap cant handle all of excess

                    uint256 buyTokens = getAmountOut(tokens_to_max_slippage, token1Reserves, token0Reserves);

                    uniVars.amountFromReserves = tokens_to_max_slippage;

                    uniVars.mintToReserves = mintAmount;

                    // swap up to slippage limit, taking excess - remainingExcess from reserves, and minting full amount

                    // to reserves

                    pair.swap(buyTokens, 0, address(this), abi.encode(uniVars));

                }

            }

        }

    }



    function uniswapMaxSlippage(

        uint256 token0,

        uint256 token1,

        uint256 offPegPerc

    )

      internal

      view

      returns (uint256)

    {

        if (isToken0) {

          if (offPegPerc >= 10**17) {

              // cap slippage

              return token0.mul(maxSlippageFactor).div(10**18);

          } else {

              // in the 5-10% off peg range, slippage is essentially 2*x (where x is percentage of pool to buy).

              // all we care about is not pushing below the peg, so underestimate

              // the amount we can sell by dividing by 3. resulting price impact

              // should be ~= offPegPerc * 2 / 3, which will keep us above the peg

              //

              // this is a conservative heuristic

              return token0.mul(offPegPerc / 3).div(10**18);

          }

        } else {

            if (offPegPerc >= 10**17) {

                return token1.mul(maxSlippageFactor).div(10**18);

            } else {

                return token1.mul(offPegPerc / 3).div(10**18);

            }

        }

    }



    /**

     * @notice given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset

     *

     * @param amountIn input amount of the asset

     * @param reserveIn reserves of the asset being sold

     * @param reserveOut reserves if the asset being purchased

     */



   function getAmountOut(

        uint amountIn,

        uint reserveIn,

        uint reserveOut

    )

        internal

        pure

        returns (uint amountOut)

    {

       require(amountIn > 0, 'UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT');

       require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');

       uint amountInWithFee = amountIn.mul(997);

       uint numerator = amountInWithFee.mul(reserveOut);

       uint denominator = reserveIn.mul(1000).add(amountInWithFee);

       amountOut = numerator / denominator;

   }





    function afterRebase(

        uint256 mintAmount,

        uint256 offPegPerc

    )

        internal

    {

        // update uniswap

        UniswapPair(uniswap_pair).sync();



        if (mintAmount > 0) {

            buyReserveAndTransfer(

                mintAmount,

                offPegPerc

            );

        }



        // call any extra functions

        for (uint i = 0; i < transactions.length; i++) {

            Transaction storage t = transactions[i];

            if (t.enabled) {

                bool result =

                    externalCall(t.destination, t.data);

                if (!result) {

                    emit TransactionFailed(t.destination, i, t.data);

                    revert("Transaction Failed");

                }

            }

        }

    }





    /**

     * @notice Calculates TWAP from uniswap

     *

     * @dev When liquidity is low, this can be manipulated by an end of block -> next block

     *      attack. We delay the activation of rebases 12 hours after liquidity incentives

     *      to reduce this attack vector. Additional there is very little supply

     *      to be able to manipulate this during that time period of highest vuln.

     */

    function getTWAP()

        internal

        returns (uint256)

    {

      (uint priceCumulative, uint32 blockTimestamp) =

         UniswapV2OracleLibrary.currentCumulativePrices(uniswap_pair, isToken0);

       uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired



       // no period check as is done in isRebaseWindow



       // overflow is desired, casting never truncates

        // cumulative price is in (uq112x112 price * seconds) units so we simply wrap it after division by time elapsed

        FixedPoint.uq112x112 memory priceAverage = FixedPoint.uq112x112(uint224((priceCumulative - priceCumulativeLast) / timeElapsed));



        priceCumulativeLast = priceCumulative;

        blockTimestampLast = blockTimestamp;



        return FixedPoint.decode144(FixedPoint.mul(priceAverage, 10**18));

    }



    /**

     * @notice Calculates current TWAP from uniswap

     *

     */

    function getCurrentTWAP()

        public

        view

        returns (uint256)

    {

      (uint priceCumulative, uint32 blockTimestamp) =

         UniswapV2OracleLibrary.currentCumulativePrices(uniswap_pair, isToken0);

       uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired



       // no period check as is done in isRebaseWindow



       // overflow is desired, casting never truncates

        // cumulative price is in (uq112x112 price * seconds) units so we simply wrap it after division by time elapsed

        FixedPoint.uq112x112 memory priceAverage = FixedPoint.uq112x112(uint224((priceCumulative - priceCumulativeLast) / timeElapsed));



        return FixedPoint.decode144(FixedPoint.mul(priceAverage, 10**18));

    }



    /**

     * @notice Sets the deviation threshold fraction. If the exchange rate given by the market

     *         oracle is within this fractional distance from the targetRate, then no supply

     *         modifications are made.

     * @param deviationThreshold_ The new exchange rate threshold fraction.

     */

    function setDeviationThreshold(uint256 deviationThreshold_)

        external

        onlyGov

    {

        require(deviationThreshold > 0);

        uint256 oldDeviationThreshold = deviationThreshold;

        deviationThreshold = deviationThreshold_;

        emit NewDeviationThreshold(oldDeviationThreshold, deviationThreshold_);

    }



    /**

     * @notice Sets the rebase lag parameter.

               It is used to dampen the applied supply adjustment by 1 / rebaseLag

               If the rebase lag R, equals 1, the smallest value for R, then the full supply

               correction is applied on each rebase cycle.

               If it is greater than 1, then a correction of 1/R of is applied on each rebase.

     * @param rebaseLag_ The new rebase lag parameter.

     */

    function setRebaseLag(uint256 rebaseLag_)

        external

        onlyGov

    {

        require(rebaseLag_ > 0);

        rebaseLag = rebaseLag_;

    }



    /**

     * @notice Sets the targetRate parameter.

     * @param targetRate_ The new target rate parameter.

     */

    function setTargetRate(uint256 targetRate_)

        external

        onlyGov

    {

        require(targetRate_ > 0);

        targetRate = targetRate_;

    }



    /**

     * @notice Sets the parameters which control the timing and frequency of

     *         rebase operations.

     *         a) the minimum time period that must elapse between rebase cycles.

     *         b) the rebase window offset parameter.

     *         c) the rebase window length parameter.

     * @param minRebaseTimeIntervalSec_ More than this much time must pass between rebase

     *        operations, in seconds.

     * @param rebaseWindowOffsetSec_ The number of seconds from the beginning of

              the rebase interval, where the rebase window begins.

     * @param rebaseWindowLengthSec_ The length of the rebase window in seconds.

     */

    function setRebaseTimingParameters(

        uint256 minRebaseTimeIntervalSec_,

        uint256 rebaseWindowOffsetSec_,

        uint256 rebaseWindowLengthSec_)

        external

        onlyGov

    {

        require(minRebaseTimeIntervalSec_ > 0);

        require(rebaseWindowOffsetSec_ < minRebaseTimeIntervalSec_);



        minRebaseTimeIntervalSec = minRebaseTimeIntervalSec_;

        rebaseWindowOffsetSec = rebaseWindowOffsetSec_;

        rebaseWindowLengthSec = rebaseWindowLengthSec_;

    }



    /**

     * @return If the latest block timestamp is within the rebase time window it, returns true.

     *         Otherwise, returns false.

     */

    function inRebaseWindow() public view returns (bool) {



        // rebasing is delayed until there is a liquid market

        _inRebaseWindow();

        return true;

    }



    function _inRebaseWindow() internal view {



        // rebasing is delayed until there is a liquid market

        require(rebasingActive, "rebasing not active");



        require(now.mod(minRebaseTimeIntervalSec) >= rebaseWindowOffsetSec, "too early");

        require(now.mod(minRebaseTimeIntervalSec) < (rebaseWindowOffsetSec.add(rebaseWindowLengthSec)), "too late");

    }



    /**

     * @return Computes in % how far off market is from peg

     */

    function computeOffPegPerc(uint256 rate)

        private

        view

        returns (uint256, bool)

    {

        if (withinDeviationThreshold(rate)) {

            return (0, false);

        }



        // indexDelta =  (rate - targetRate) / targetRate

        if (rate > targetRate) {

            return (rate.sub(targetRate).mul(10**18).div(targetRate), true);

        } else {

            return (targetRate.sub(rate).mul(10**18).div(targetRate), false);

        }

    }



    /**

     * @param rate The current exchange rate, an 18 decimal fixed point number.

     * @return If the rate is within the deviation threshold from the target rate, returns true.

     *         Otherwise, returns false.

     */

    function withinDeviationThreshold(uint256 rate)

        private

        view

        returns (bool)

    {

        uint256 absoluteDeviationThreshold = targetRate.mul(deviationThreshold)

            .div(10 ** 18);



        return (rate >= targetRate && rate.sub(targetRate) < absoluteDeviationThreshold)

            || (rate < targetRate && targetRate.sub(rate) < absoluteDeviationThreshold);

    }



    /* - Constructor Helpers - */



    // calculates the CREATE2 address for a pair without making any external calls

    function pairFor(

        address factory,

        address token0,

        address token1

    )

        internal

        pure

        returns (address pair)

    {

        pair = address(uint(keccak256(abi.encodePacked(

                hex'ff',

                factory,

                keccak256(abi.encodePacked(token0, token1)),

                hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f' // init code hash

            ))));

    }



    // returns sorted token addresses, used to handle return values from pairs sorted in this order

    function sortTokens(

        address tokenA,

        address tokenB

    )

        internal

        pure

        returns (address token0, address token1)

    {

        require(tokenA != tokenB, 'UniswapV2Library: IDENTICAL_ADDRESSES');

        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);

        require(token0 != address(0), 'UniswapV2Library: ZERO_ADDRESS');

    }



    /* -- Rebase helpers -- */



    /**

     * @notice Adds a transaction that gets called for a downstream receiver of rebases

     * @param destination Address of contract destination

     * @param data Transaction data payload

     */

    function addTransaction(address destination, bytes calldata data)

        external

        onlyGov

    {

        transactions.push(Transaction({

            enabled: true,

            destination: destination,

            data: data

        }));

    }





    /**

     * @param index Index of transaction to remove.

     *              Transaction ordering may have changed since adding.

     */

    function removeTransaction(uint index)

        external

        onlyGov

    {

        require(index < transactions.length, "index out of bounds");



        if (index < transactions.length - 1) {

            transactions[index] = transactions[transactions.length - 1];

        }



        transactions.length--;

    }



    /**

     * @param index Index of transaction. Transaction ordering may have changed since adding.

     * @param enabled True for enabled, false for disabled.

     */

    function setTransactionEnabled(uint index, bool enabled)

        external

        onlyGov

    {

        require(index < transactions.length, "index must be in range of stored tx list");

        transactions[index].enabled = enabled;

    }



    /**

     * @dev wrapper to call the encoded transactions on downstream consumers.

     * @param destination Address of destination contract.

     * @param data The encoded data payload.

     * @return True on success

     */

    function externalCall(address destination, bytes memory data)

        internal

        returns (bool)

    {

        bool result;

        assembly {  // solhint-disable-line no-inline-assembly

            // "Allocate" memory for output

            // (0x40 is where "free memory" pointer is stored by convention)

            let outputAddress := mload(0x40)



            // First 32 bytes are the padded length of data, so exclude that

            let dataAddress := add(data, 32)



            result := call(

                // 34710 is the value that solidity is currently emitting

                // It includes callGas (700) + callVeryLow (3, to pay for SUB)

                // + callValueTransferGas (9000) + callNewAccountGas

                // (25000, in case the destination address does not exist and needs creating)

                sub(gas, 34710),





                destination,

                0, // transfer value in wei

                dataAddress,

                mload(data),  // Size of the input, in bytes. Stored in position 0 of the array.

                outputAddress,

                0  // Output is ignored, therefore the output size is zero

            )

        }

        return result;

    }

}

interface TreasuryPool {

    function updateNextRewards(uint256 amount) external;

}

contract GAMERReserves {



    // Token that serves as a reserve for GAMER

    address public reserveToken;



    address public gov;



    address public pendingGov;



    address public rebaser;



    address public gamerAddress;



    address public treasuryPool;



    /*** Gov Events ***/



    /**

     * @notice Event emitted when pendingGov is changed

     */

    event NewPendingGov(address oldPendingGov, address newPendingGov);



    /**

     * @notice Event emitted when gov is changed

     */

    event NewGov(address oldGov, address newGov);



    /**

     * @notice Event emitted when TreasuryPool is changed

     */

    event NewTreasuryPool(address oldTreasuryPool, address newTreasuryPool);



    /**

     * @notice Event emitted when rebaser is changed

     */

    event NewRebaser(address oldRebaser, address newRebaser);





    modifier onlyGov() {

        require(msg.sender == gov);

        _;

    }



    modifier onlyRebaser() {

        require(msg.sender == rebaser);

        _;

    }



    constructor(

        address reserveToken_,

        address gamerAddress_

    )

        public

    {

        reserveToken = reserveToken_;

        gamerAddress = gamerAddress_;

        gov = msg.sender;

    }



    function _setRebaser(address rebaser_)

        external

        onlyGov

    {

        address oldRebaser = rebaser;

        GAMERTokenInterface(gamerAddress).decreaseAllowance(oldRebaser, uint256(-1));

        rebaser = rebaser_;

        GAMERTokenInterface(gamerAddress).approve(rebaser_, uint256(-1));

        emit NewRebaser(oldRebaser, rebaser_);

    }



    /** @notice sets the pendingGov

     * @param pendingGov_ The address of the rebaser contract to use for authentication.

     */

    function _setPendingGov(address pendingGov_)

        external

        onlyGov

    {

        address oldPendingGov = pendingGov;

        pendingGov = pendingGov_;

        emit NewPendingGov(oldPendingGov, pendingGov_);

    }



    /**

     * @notice lets msg.sender accept governance

     */

    function _acceptGov()

        external

    {

        require(msg.sender == pendingGov, "!pending");

        address oldGov = gov;

        gov = pendingGov;

        pendingGov = address(0);

        emit NewGov(oldGov, gov);

    }



    /** @notice sets the treasuryPool

     * @param treasuryPool_ The address of the treasury pool contract.

     */

    function _setTreasuryPool(address treasuryPool_)

        external

        onlyGov

    {

        address oldTreasuryPool = treasuryPool;

        treasuryPool = treasuryPool_;

        emit NewTreasuryPool(oldTreasuryPool, treasuryPool_);

    }



    /// @notice Moves all tokens to a new reserve contract

    function migrateReserves(

        address newReserve,

        address[] memory tokens

    )

        public

        onlyGov

    {

        for (uint256 i = 0; i < tokens.length; i++) {

            IERC20 token =  IERC20(tokens[i]);

            uint256 bal = token.balanceOf(address(this));

            SafeERC20.safeTransfer(token, newReserve, bal);

        }

    }



    /// @notice Gets the current amount of reserves token held by this contract

    function reserves()

        public

        view

        returns (uint256)

    {

        return IERC20(reserveToken).balanceOf(address(this));

    }



        /// @notice Gets the current amount of reserves token held by this contract

    function distributeTreasuryReward(uint256 amount)

        public

        onlyRebaser

    {

        IERC20(reserveToken).transfer(treasuryPool, amount);

        TreasuryPool(treasuryPool).updateNextRewards(amount);

    }

}

contract GAMERGovernanceStorage {

    /// @notice A record of each accounts delegate

    mapping (address => address) internal _delegates;



    /// @notice A checkpoint for marking number of votes from a given block

    struct Checkpoint {

        uint32 fromBlock;

        uint256 votes;

    }



    /// @notice A record of votes checkpoints for each account, by index

    mapping (address => mapping (uint32 => Checkpoint)) public checkpoints;



    /// @notice The number of checkpoints for each account

    mapping (address => uint32) public numCheckpoints;



    /// @notice The EIP-712 typehash for the contract's domain

    bytes32 public constant DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,uint256 chainId,address verifyingContract)");



    /// @notice The EIP-712 typehash for the delegation struct used by the contract

    bytes32 public constant DELEGATION_TYPEHASH = keccak256("Delegation(address delegatee,uint256 nonce,uint256 expiry)");



    /// @notice A record of states for signing / validating signatures

    mapping (address => uint) public nonces;

}

contract GAMERTokenStorage {



    using SafeMath for uint256;



    /**

     * @dev Guard variable for re-entrancy checks. Not currently used

     */

    bool internal _notEntered;



    /**

     * @notice EIP-20 token name for this token

     */

    string public name;



    /**

     * @notice EIP-20 token symbol for this token

     */

    string public symbol;



    /**

     * @notice EIP-20 token decimals for this token

     */

    uint8 public decimals;



    /**

     * @notice Governor for this contract

     */

    address public gov;



    /**

     * @notice Pending governance for this contract

     */

    address public pendingGov;



    /**

     * @notice Approved rebaser for this contract

     */

    address public rebaser;



    /**

     * @notice Reserve address of GAMER protocol

     */

    address public incentivizer;



    /**

     * @notice stakingPool address of GAMER protocol

     */

    address public stakingPool;



    /**

     * @notice teamPool address of GAMER protocol

     */

    address public teamPool;



    /**

     * @notice dev address of GAMER protocol

     */

    address public dev;



    /**

     * @notice Total supply of GAMERs

     */

    uint256 internal _totalSupply;



    /**

     * @notice Internal decimals used to handle scaling factor

     */

    uint256 public constant internalDecimals = 10**24;



    /**

     * @notice Used for percentage maths

     */

    uint256 public constant BASE = 10**18;



    /**

     * @notice Scaling factor that adjusts everyone's balances

     */

    uint256 public gamersScalingFactor;



    mapping (address => uint256) internal _gamerBalances;



    mapping (address => mapping (address => uint256)) internal _allowedFragments;



    uint256 public initSupply;



}

contract GAMERTokenInterface is GAMERTokenStorage, GAMERGovernanceStorage {



    /// @notice An event thats emitted when an account changes its delegate

    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);



    /// @notice An event thats emitted when a delegate account's vote balance changes

    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);



    /**

     * @notice Event emitted when tokens are rebased

     */

    event Rebase(uint256 epoch, uint256 prevGrapsScalingFactor, uint256 newGrapsScalingFactor);



    /*** Gov Events ***/



    /**

     * @notice Event emitted when pendingGov is changed

     */

    event NewPendingGov(address oldPendingGov, address newPendingGov);



    /**

     * @notice Event emitted when gov is changed

     */

    event NewGov(address oldGov, address newGov);



    /**

     * @notice Sets the rebaser contract

     */

    event NewRebaser(address oldRebaser, address newRebaser);



    /**

     * @notice Sets the incentivizer contract

     */

    event NewIncentivizer(address oldIncentivizer, address newIncentivizer);



    /**

     * @notice Sets the StakingPool contract

     */

    event NewStakingPool(address oldStakingPool, address newStakingPool);



    /**

     * @notice Sets the TeamPool contract

     */

    event NewTeamPool(address oldTeamPool, address newTeamPool);



    /**

     * @notice Sets the Dev contract

     */

    event NewDev(address oldDev, address newDev);



    /* - ERC20 Events - */



    /**

     * @notice EIP20 Transfer event

     */

    event Transfer(address indexed from, address indexed to, uint amount);



    /**

     * @notice EIP20 Approval event

     */

    event Approval(address indexed owner, address indexed spender, uint amount);



    /* - Extra Events - */

    /**

     * @notice Tokens minted event

     */

    event Mint(address to, uint256 amount);



    // Public functions

    function totalSupply() external view returns (uint256);

    function transfer(address to, uint256 value) external returns(bool);

    function transferFrom(address from, address to, uint256 value) external returns(bool);

    function balanceOf(address who) external view returns(uint256);

    function balanceOfUnderlying(address who) external view returns(uint256);

    function allowance(address owner_, address spender) external view returns(uint256);

    function approve(address spender, uint256 value) external returns (bool);

    function increaseAllowance(address spender, uint256 addedValue) external returns (bool);

    function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool);

    function maxScalingFactor() external view returns (uint256);



    /* - Governance Functions - */

    function getPriorVotes(address account, uint blockNumber) external view returns (uint256);

    function delegateBySig(address delegatee, uint nonce, uint expiry, uint8 v, bytes32 r, bytes32 s) external;

    function delegate(address delegatee) external;

    function delegates(address delegator) external view returns (address);

    function getCurrentVotes(address account) external view returns (uint256);



    /* - Permissioned/Governance functions - */

    function mint(address to, uint256 amount) external returns (bool);

    function rebase(uint256 epoch, uint256 indexDelta, bool positive) external returns (uint256);

    function _setRebaser(address rebaser_) external;

    function _setIncentivizer(address incentivizer_) external;

    function _setPendingGov(address pendingGov_) external;

    function _acceptGov() external;

}

contract GAMERGovernanceToken is GAMERTokenInterface {



      /// @notice An event thats emitted when an account changes its delegate

    event DelegateChanged(address indexed delegator, address indexed fromDelegate, address indexed toDelegate);



    /// @notice An event thats emitted when a delegate account's vote balance changes

    event DelegateVotesChanged(address indexed delegate, uint previousBalance, uint newBalance);



    /**

     * @notice Delegate votes from `msg.sender` to `delegatee`

     * @param delegator The address to get delegatee for

     */

    function delegates(address delegator)

        external

        view

        returns (address)

    {

        return _delegates[delegator];

    }



   /**

    * @notice Delegate votes from `msg.sender` to `delegatee`

    * @param delegatee The address to delegate votes to

    */

    function delegate(address delegatee) external {

        return _delegate(msg.sender, delegatee);

    }



    /**

     * @notice Delegates votes from signatory to `delegatee`

     * @param delegatee The address to delegate votes to

     * @param nonce The contract state required to match the signature

     * @param expiry The time at which to expire the signature

     * @param v The recovery byte of the signature

     * @param r Half of the ECDSA signature pair

     * @param s Half of the ECDSA signature pair

     */

    function delegateBySig(

        address delegatee,

        uint nonce,

        uint expiry,

        uint8 v,

        bytes32 r,

        bytes32 s

    )

        external

    {

        bytes32 domainSeparator = keccak256(

            abi.encode(

                DOMAIN_TYPEHASH,

                keccak256(bytes(name)),

                getChainId(),

                address(this)

            )

        );



        bytes32 structHash = keccak256(

            abi.encode(

                DELEGATION_TYPEHASH,

                delegatee,

                nonce,

                expiry

            )

        );



        bytes32 digest = keccak256(

            abi.encodePacked(

                "\x19\x01",

                domainSeparator,

                structHash

            )

        );



        address signatory = ecrecover(digest, v, r, s);

        require(signatory != address(0), "GAMER::delegateBySig: invalid signature");

        require(nonce == nonces[signatory]++, "GAMER::delegateBySig: invalid nonce");

        require(now <= expiry, "GAMER::delegateBySig: signature expired");

        return _delegate(signatory, delegatee);

    }



    /**

     * @notice Gets the current votes balance for `account`

     * @param account The address to get votes balance

     * @return The number of current votes for `account`

     */

    function getCurrentVotes(address account)

        external

        view

        returns (uint256)

    {

        uint32 nCheckpoints = numCheckpoints[account];

        return nCheckpoints > 0 ? checkpoints[account][nCheckpoints - 1].votes : 0;

    }



    /**

     * @notice Determine the prior number of votes for an account as of a block number

     * @dev Block number must be a finalized block or else this function will revert to prevent misinformation.

     * @param account The address of the account to check

     * @param blockNumber The block number to get the vote balance at

     * @return The number of votes the account had as of the given block

     */

    function getPriorVotes(address account, uint blockNumber)

        external

        view

        returns (uint256)

    {

        require(blockNumber < block.number, "GAMER::getPriorVotes: not yet determined");



        uint32 nCheckpoints = numCheckpoints[account];

        if (nCheckpoints == 0) {

            return 0;

        }



        // First check most recent balance

        if (checkpoints[account][nCheckpoints - 1].fromBlock <= blockNumber) {

            return checkpoints[account][nCheckpoints - 1].votes;

        }



        // Next check implicit zero balance

        if (checkpoints[account][0].fromBlock > blockNumber) {

            return 0;

        }



        uint32 lower = 0;

        uint32 upper = nCheckpoints - 1;

        while (upper > lower) {

            uint32 center = upper - (upper - lower) / 2; // ceil, avoiding overflow

            Checkpoint memory cp = checkpoints[account][center];

            if (cp.fromBlock == blockNumber) {

                return cp.votes;

            } else if (cp.fromBlock < blockNumber) {

                lower = center;

            } else {

                upper = center - 1;

            }

        }

        return checkpoints[account][lower].votes;

    }



    function _delegate(address delegator, address delegatee)

        internal

    {

        address currentDelegate = _delegates[delegator];

        uint256 delegatorBalance = _gamerBalances[delegator]; // balance of underlying GAMERs (not scaled);

        _delegates[delegator] = delegatee;



        emit DelegateChanged(delegator, currentDelegate, delegatee);



        _moveDelegates(currentDelegate, delegatee, delegatorBalance);

    }



    function _moveDelegates(address srcRep, address dstRep, uint256 amount) internal {

        if (srcRep != dstRep && amount > 0) {

            if (srcRep != address(0)) {

                // decrease old representative

                uint32 srcRepNum = numCheckpoints[srcRep];

                uint256 srcRepOld = srcRepNum > 0 ? checkpoints[srcRep][srcRepNum - 1].votes : 0;

                uint256 srcRepNew = srcRepOld.sub(amount);

                _writeCheckpoint(srcRep, srcRepNum, srcRepOld, srcRepNew);

            }



            if (dstRep != address(0)) {

                // increase new representative

                uint32 dstRepNum = numCheckpoints[dstRep];

                uint256 dstRepOld = dstRepNum > 0 ? checkpoints[dstRep][dstRepNum - 1].votes : 0;

                uint256 dstRepNew = dstRepOld.add(amount);

                _writeCheckpoint(dstRep, dstRepNum, dstRepOld, dstRepNew);

            }

        }

    }



    function _writeCheckpoint(

        address delegatee,

        uint32 nCheckpoints,

        uint256 oldVotes,

        uint256 newVotes

    )

        internal

    {

        uint32 blockNumber = safe32(block.number, "GAMER::_writeCheckpoint: block number exceeds 32 bits");



        if (nCheckpoints > 0 && checkpoints[delegatee][nCheckpoints - 1].fromBlock == blockNumber) {

            checkpoints[delegatee][nCheckpoints - 1].votes = newVotes;

        } else {

            checkpoints[delegatee][nCheckpoints] = Checkpoint(blockNumber, newVotes);

            numCheckpoints[delegatee] = nCheckpoints + 1;

        }



        emit DelegateVotesChanged(delegatee, oldVotes, newVotes);

    }



    function safe32(uint n, string memory errorMessage) internal pure returns (uint32) {

        require(n < 2**32, errorMessage);

        return uint32(n);

    }



    function getChainId() internal pure returns (uint) {

        uint256 chainId;

        assembly { chainId := chainid() }

        return chainId;

    }

}

contract GAMERToken is GAMERGovernanceToken {

    // Modifiers

    modifier onlyGov() {

        require(msg.sender == gov, 'not gov');

        _;

    }



    modifier onlyRebaser() {

        require(msg.sender == rebaser);

        _;

    }



    modifier onlyMinter() {

        require(msg.sender == rebaser || msg.sender == incentivizer || msg.sender == stakingPool || msg.sender == teamPool || msg.sender == dev || msg.sender == gov, "not minter");

        _;

    }



    modifier validRecipient(address to) {

        require(to != address(0x0));

        require(to != address(this));

        _;

    }



    function initialize(

        string memory name_,

        string memory symbol_,

        uint8 decimals_

    )

        public

    {

        require(gamersScalingFactor == 0, "already initialized");

        name = name_;

        symbol = symbol_;

        decimals = decimals_;

    }



    /**

    * @notice Computes the current totalSupply

    */

    function totalSupply()

        external

        view

        returns (uint256)

    {

        return _totalSupply.div(10**24/ (BASE));

    }

    

    /**

    * @notice Computes the current max scaling factor

    */

    function maxScalingFactor()

        external

        view

        returns (uint256)

    {

        return _maxScalingFactor();

    }



    function _maxScalingFactor()

        internal

        view

        returns (uint256)

    {

        // scaling factor can only go up to 2**256-1 = initSupply * gamersScalingFactor

        // this is used to check if gamersScalingFactor will be too high to compute balances when rebasing.

        return uint256(-1) / initSupply;

    }



    /**

    * @notice Mints new tokens, increasing totalSupply, initSupply, and a users balance.

    * @dev Limited to onlyMinter modifier

    */

    function mint(address to, uint256 amount)

        external

        onlyMinter

        returns (bool)

    {

        _mint(to, amount);

        return true;

    }



    function _mint(address to, uint256 amount)

        internal

    {

      // increase totalSupply

      _totalSupply = _totalSupply.add(amount.mul(10**24/ (BASE)));



      // get underlying value

      uint256 gamerValue = amount.mul(internalDecimals).div(gamersScalingFactor);



      // increase initSupply

      initSupply = initSupply.add(gamerValue);



      // make sure the mint didnt push maxScalingFactor too low

      require(gamersScalingFactor <= _maxScalingFactor(), "max scaling factor too low");



      // add balance

      _gamerBalances[to] = _gamerBalances[to].add(gamerValue);

      emit Transfer(address(0), to, amount);

    

      // add delegates to the minter

      _moveDelegates(address(0), _delegates[to], gamerValue);

      emit Mint(to, amount);

    }



    /* - ERC20 functionality - */



    /**

    * @dev Transfer tokens to a specified address.

    * @param to The address to transfer to.

    * @param value The amount to be transferred.

    * @return True on success, false otherwise.

    */

    function transfer(address to, uint256 value)

        external

        validRecipient(to)

        returns (bool)

    {

        // underlying balance is stored in gamers, so divide by current scaling factor



        // note, this means as scaling factor grows, dust will be untransferrable.

        // minimum transfer value == gamersScalingFactor / 1e24;



        // get amount in underlying

        uint256 gamerValue = value.mul(internalDecimals).div(gamersScalingFactor);



        // sub from balance of sender

        _gamerBalances[msg.sender] = _gamerBalances[msg.sender].sub(gamerValue);



        // add to balance of receiver

        _gamerBalances[to] = _gamerBalances[to].add(gamerValue);

        emit Transfer(msg.sender, to, value);



        _moveDelegates(_delegates[msg.sender], _delegates[to], gamerValue);

        return true;

    }



    /**

    * @dev Transfer tokens from one address to another.

    * @param from The address you want to send tokens from.

    * @param to The address you want to transfer to.

    * @param value The amount of tokens to be transferred.

    */

    function transferFrom(address from, address to, uint256 value)

        external

        validRecipient(to)

        returns (bool)

    {

        // decrease allowance

        _allowedFragments[from][msg.sender] = _allowedFragments[from][msg.sender].sub(value);



        // get value in gamers

        uint256 gamerValue = value.mul(internalDecimals).div(gamersScalingFactor);



        // sub from from

        _gamerBalances[from] = _gamerBalances[from].sub(gamerValue);

        _gamerBalances[to] = _gamerBalances[to].add(gamerValue);

        emit Transfer(from, to, value);



        _moveDelegates(_delegates[from], _delegates[to], gamerValue);

        return true;

    }



    /**

    * @param who The address to query.

    * @return The balance of the specified address.

    */

    function balanceOf(address who)

      external

      view

      returns (uint256)

    {

      return _gamerBalances[who].mul(gamersScalingFactor).div(internalDecimals);

    }



    /** @notice Currently returns the internal storage amount

    * @param who The address to query.

    * @return The underlying balance of the specified address.

    */

    function balanceOfUnderlying(address who)

      external

      view

      returns (uint256)

    {

      return _gamerBalances[who];

    }



    /**

     * @dev Function to check the amount of tokens that an owner has allowed to a spender.

     * @param owner_ The address which owns the funds.

     * @param spender The address which will spend the funds.

     * @return The number of tokens still available for the spender.

     */

    function allowance(address owner_, address spender)

        external

        view

        returns (uint256)

    {

        return _allowedFragments[owner_][spender];

    }



    /**

     * @dev Approve the passed address to spend the specified amount of tokens on behalf of

     * msg.sender. This method is included for ERC20 compatibility.

     * increaseAllowance and decreaseAllowance should be used instead.

     * Changing an allowance with this method brings the risk that someone may transfer both

     * the old and the new allowance - if they are both greater than zero - if a transfer

     * transaction is mined before the later approve() call is mined.

     *

     * @param spender The address which will spend the funds.

     * @param value The amount of tokens to be spent.

     */

    function approve(address spender, uint256 value)

        external

        returns (bool)

    {

        _allowedFragments[msg.sender][spender] = value;

        emit Approval(msg.sender, spender, value);

        return true;

    }



    /**

     * @dev Increase the amount of tokens that an owner has allowed to a spender.

     * This method should be used instead of approve() to avoid the double approval vulnerability

     * described above.

     * @param spender The address which will spend the funds.

     * @param addedValue The amount of tokens to increase the allowance by.

     */

    function increaseAllowance(address spender, uint256 addedValue)

        external

        returns (bool)

    {

        _allowedFragments[msg.sender][spender] =

            _allowedFragments[msg.sender][spender].add(addedValue);

        emit Approval(msg.sender, spender, _allowedFragments[msg.sender][spender]);

        return true;

    }



    /**

     * @dev Decrease the amount of tokens that an owner has allowed to a spender.

     *

     * @param spender The address which will spend the funds.

     * @param subtractedValue The amount of tokens to decrease the allowance by.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue)

        external

        returns (bool)

    {

        uint256 oldValue = _allowedFragments[msg.sender][spender];

        if (subtractedValue >= oldValue) {

            _allowedFragments[msg.sender][spender] = 0;

        } else {

            _allowedFragments[msg.sender][spender] = oldValue.sub(subtractedValue);

        }

        emit Approval(msg.sender, spender, _allowedFragments[msg.sender][spender]);

        return true;

    }



    /* - Governance Functions - */



    /** @notice sets the rebaser

     * @param rebaser_ The address of the rebaser contract to use for authentication.

     */

    function _setRebaser(address rebaser_)

        external

        onlyGov

    {

        address oldRebaser = rebaser;

        rebaser = rebaser_;

        emit NewRebaser(oldRebaser, rebaser_);

    }



    /** @notice sets the incentivizer

     * @param incentivizer_ The address of the incentivizer contract to use for authentication.

     */

    function _setIncentivizer(address incentivizer_)

        external

        onlyGov

    {

        address oldIncentivizer = incentivizer;

        incentivizer = incentivizer_;

        emit NewIncentivizer(oldIncentivizer, incentivizer_);

    }



    /** @notice sets the stakingPool

     * @param stakingPool_ The address of the stakingPool contract to use for authentication.

     */

    function _setStakingPool(address stakingPool_)

        external

        onlyGov

    {

        address oldStakingPool = stakingPool;

        stakingPool = stakingPool_;

        emit NewStakingPool(oldStakingPool, stakingPool_);

    }



    /** @notice sets the teamPool

     * @param teamPool_ The address of the teamPool contract to use for authentication.

     */

    function _setTeamPool(address teamPool_)

        external

        onlyGov

    {

        address oldTeamPool = teamPool;

        teamPool = teamPool_;

        emit NewTeamPool(oldTeamPool, teamPool_);

    }



    /** @notice sets the dev

     * @param dev_ The address of the dev contract to use for authentication.

     */

    function _setDev(address dev_)

        external

        onlyGov

    {

        address oldDev = dev;

        dev = dev_;

        emit NewDev(oldDev, dev_);

    }



    /** @notice sets the pendingGov

     * @param pendingGov_ The address of the rebaser contract to use for authentication.

     */

    function _setPendingGov(address pendingGov_)

        external

        onlyGov

    {

        address oldPendingGov = pendingGov;

        pendingGov = pendingGov_;

        emit NewPendingGov(oldPendingGov, pendingGov_);

    }



    /** @notice lets msg.sender accept governance

     *

     */

    function _acceptGov()

        external

    {

        require(msg.sender == pendingGov, "!pending");

        address oldGov = gov;

        gov = pendingGov;

        pendingGov = address(0);

        emit NewGov(oldGov, gov);

    }



    /* - Extras - */



    /**

    * @notice Initiates a new rebase operation, provided the minimum time period has elapsed.

    *

    * @dev The supply adjustment equals (totalSupply * DeviationFromTargetRate) / rebaseLag

    *      Where DeviationFromTargetRate is (MarketOracleRate - targetRate) / targetRate

    *      and targetRate is CpiOracleRate / baseCpi

    */

    function rebase(

        uint256 epoch,

        uint256 indexDelta,

        bool positive

    )

        external

        onlyRebaser

        returns (uint256)

    {

        if (indexDelta == 0) {

          emit Rebase(epoch, gamersScalingFactor, gamersScalingFactor);

          return _totalSupply;

        }



        uint256 prevGrapsScalingFactor = gamersScalingFactor;



        if (!positive) {

           gamersScalingFactor = gamersScalingFactor.mul(BASE.sub(indexDelta)).div(BASE);

        } else {

            uint256 newScalingFactor = gamersScalingFactor.mul(BASE.add(indexDelta)).div(BASE);

            if (newScalingFactor < _maxScalingFactor()) {

                gamersScalingFactor = newScalingFactor;

            } else {

              gamersScalingFactor = _maxScalingFactor();

            }

        }



        _totalSupply = initSupply.mul(gamersScalingFactor).div(BASE);

        emit Rebase(epoch, prevGrapsScalingFactor, gamersScalingFactor);

        return _totalSupply;

    }

}

contract GAMER is GAMERToken {

    /**

     * @notice Initialize the new money market

     * @param name_ ERC-20 name of this token

     * @param symbol_ ERC-20 symbol of this token

     * @param decimals_ ERC-20 decimal precision of this token

     */

    function initialize(

        string memory name_,

        string memory symbol_,

        uint8 decimals_,

        address initial_owner,

        uint256 initSupply_

    )

        public

    {

        require(initSupply_ > 0, "0 init supply");



        super.initialize(name_, symbol_, decimals_);



        initSupply = initSupply_.mul(10**24/ (BASE));

        _totalSupply = initSupply;

        gamersScalingFactor = BASE;

        _gamerBalances[initial_owner] = initSupply_.mul(10**24 / (BASE));



        // owner renounces ownership after deployment as they need to set

        // rebaser and incentivizer

        // gov = gov_;

    }

}
