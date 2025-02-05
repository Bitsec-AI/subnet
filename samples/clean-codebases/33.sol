pragma solidity 0.6.12;

abstract contract Context {

    function _msgSender() internal view virtual returns (address payable) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691

        return msg.data;

    }

}

interface ICommittee {

	event CommitteeChange(address indexed addr, uint256 weight, bool certification, bool inCommittee);

	event CommitteeSnapshot(address[] addrs, uint256[] weights, bool[] certification);



	// No external functions



	/*

     * External functions

     */



	/// @dev Called by: Elections contract

	/// Notifies a weight change of certification change of a member

	function memberWeightChange(address addr, uint256 weight) external /* onlyElectionsContract onlyWhenActive */;



	function memberCertificationChange(address addr, bool isCertified) external /* onlyElectionsContract onlyWhenActive */;



	/// @dev Called by: Elections contract

	/// Notifies a a member removal for example due to voteOut / voteUnready

	function removeMember(address addr) external returns (bool memberRemoved, uint removedMemberEffectiveStake, bool removedMemberCertified)/* onlyElectionContract */;



	/// @dev Called by: Elections contract

	/// Notifies a new member applicable for committee (due to registration, unbanning, certification change)

	function addMember(address addr, uint256 weight, bool isCertified) external returns (bool memberAdded)  /* onlyElectionsContract */;



	/// @dev Called by: Elections contract

	/// Checks if addMember() would add a the member to the committee

	function checkAddMember(address addr, uint256 weight) external view returns (bool wouldAddMember);



	/// @dev Called by: Elections contract

	/// Returns the committee members and their weights

	function getCommittee() external view returns (address[] memory addrs, uint256[] memory weights, bool[] memory certification);



	function getCommitteeStats() external view returns (uint generalCommitteeSize, uint certifiedCommitteeSize, uint totalStake);



	function getMemberInfo(address addr) external view returns (bool inCommittee, uint weight, bool isCertified, uint totalCommitteeWeight);



	function emitCommitteeSnapshot() external;



	/*

	 * Governance functions

	 */



	event MaxCommitteeSizeChanged(uint8 newValue, uint8 oldValue);



	function setMaxCommitteeSize(uint8 maxCommitteeSize) external /* onlyFunctionalManager onlyWhenActive */;



	function getMaxCommitteeSize() external view returns (uint8);

}

interface IContractRegistry {



	event ContractAddressUpdated(string contractName, address addr, bool managedContract);

	event ManagerChanged(string role, address newManager);

	event ContractRegistryUpdated(address newContractRegistry);



	/*

	* External functions

	*/



	/// @dev updates the contracts address and emits a corresponding event

	/// managedContract indicates whether the contract is managed by the registry and notified on changes

	function setContract(string calldata contractName, address addr, bool managedContract) external /* onlyAdmin */;



	/// @dev returns the current address of the given contracts

	function getContract(string calldata contractName) external view returns (address);



	/// @dev returns the list of contract addresses managed by the registry

	function getManagedContracts() external view returns (address[] memory);



	function setManager(string calldata role, address manager) external /* onlyAdmin */;



	function getManager(string calldata role) external view returns (address);



	function lockContracts() external /* onlyAdmin */;



	function unlockContracts() external /* onlyAdmin */;



	function setNewContractRegistry(IContractRegistry newRegistry) external /* onlyAdmin */;



	function getPreviousContractRegistry() external view returns (address);



}

interface IDelegations /* is IStakeChangeNotifier */ {



    // Delegation state change events

	event DelegatedStakeChanged(address indexed addr, uint256 selfDelegatedStake, uint256 delegatedStake, address indexed delegator, uint256 delegatorContributedStake);



    // Function calls

	event Delegated(address indexed from, address indexed to);



	/*

     * External functions

     */



	/// @dev Stake delegation

	function delegate(address to) external /* onlyWhenActive */;



	function refreshStake(address addr) external /* onlyWhenActive */;



	function getDelegatedStake(address addr) external view returns (uint256);



	function getDelegation(address addr) external view returns (address);



	function getDelegationInfo(address addr) external view returns (address delegation, uint256 delegatorStake);



	function getTotalDelegatedStake() external view returns (uint256) ;



	/*

	 * Governance functions

	 */



	event DelegationsImported(address[] from, address indexed to);



	event DelegationInitialized(address indexed from, address indexed to);



	function importDelegations(address[] calldata from, address to) external /* onlyMigrationManager onlyDuringDelegationImport */;



	function initDelegation(address from, address to) external /* onlyInitializationAdmin */;

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

interface ILockable {



    event Locked();

    event Unlocked();



    function lock() external /* onlyLockOwner */;

    function unlock() external /* onlyLockOwner */;

    function isLocked() view external returns (bool);



}

interface IMigratableStakingContract {

    /// @dev Returns the address of the underlying staked token.

    /// @return IERC20 The address of the token.

    function getToken() external view returns (IERC20);



    /// @dev Stakes ORBS tokens on behalf of msg.sender. This method assumes that the user has already approved at least

    /// the required amount using ERC20 approve.

    /// @param _stakeOwner address The specified stake owner.

    /// @param _amount uint256 The number of tokens to stake.

    function acceptMigration(address _stakeOwner, uint256 _amount) external;



    event AcceptedMigration(address indexed stakeOwner, uint256 amount, uint256 totalStakedAmount);

}

interface IProtocolWallet {

    event FundsAddedToPool(uint256 added, uint256 total);



    /*

    * External functions

    */



    /// @dev Returns the address of the underlying staked token.

    /// @return balance uint256 the balance

    function getBalance() external view returns (uint256 balance);



    /// @dev Transfers the given amount of orbs tokens form the sender to this contract an update the pool.

    function topUp(uint256 amount) external;



    /// @dev Withdraw from pool to a the sender's address, limited by the pool's MaxRate.

    /// A maximum of MaxRate x time period since the last Orbs transfer may be transferred out.

    function withdraw(uint256 amount) external; /* onlyClient */





    /*

    * Governance functions

    */



    event ClientSet(address client);

    event MaxAnnualRateSet(uint256 maxAnnualRate);

    event EmergencyWithdrawal(address addr);

    event OutstandingTokensReset(uint256 startTime);



    /// @dev Sets a new transfer rate for the Orbs pool.

    function setMaxAnnualRate(uint256 annual_rate) external; /* onlyMigrationManager */



    function getMaxAnnualRate() external view returns (uint256);



    /// @dev transfer the entire pool's balance to a new wallet.

    function emergencyWithdraw() external; /* onlyMigrationManager */



    /// @dev sets the address of the new contract

    function setClient(address client) external; /* onlyFunctionalManager */



    function resetOutstandingTokens(uint256 startTime) external; /* onlyMigrationOwner */



    }

interface IStakingContract {

    /// @dev Stakes ORBS tokens on behalf of msg.sender. This method assumes that the user has already approved at least

    /// the required amount using ERC20 approve.

    /// @param _amount uint256 The amount of tokens to stake.

    function stake(uint256 _amount) external;



    /// @dev Unstakes ORBS tokens from msg.sender. If successful, this will start the cooldown period, after which

    /// msg.sender would be able to withdraw all of his tokens.

    /// @param _amount uint256 The amount of tokens to unstake.

    function unstake(uint256 _amount) external;



    /// @dev Requests to withdraw all of staked ORBS tokens back to msg.sender. Stake owners can withdraw their ORBS

    /// tokens only after previously unstaking them and after the cooldown period has passed (unless the contract was

    /// requested to release all stakes).

    function withdraw() external;



    /// @dev Restakes unstaked ORBS tokens (in or after cooldown) for msg.sender.

    function restake() external;



    /// @dev Distributes staking rewards to a list of addresses by directly adding rewards to their stakes. This method

    /// assumes that the user has already approved at least the required amount using ERC20 approve. Since this is a

    /// convenience method, we aren't concerned about reaching block gas limit by using large lists. We assume that

    /// callers will be able to properly batch/paginate their requests.

    /// @param _totalAmount uint256 The total amount of rewards to distributes.

    /// @param _stakeOwners address[] The addresses of the stake owners.

    /// @param _amounts uint256[] The amounts of the rewards.

    function distributeRewards(uint256 _totalAmount, address[] calldata _stakeOwners, uint256[] calldata _amounts) external;



    /// @dev Returns the stake of the specified stake owner (excluding unstaked tokens).

    /// @param _stakeOwner address The address to check.

    /// @return uint256 The total stake.

    function getStakeBalanceOf(address _stakeOwner) external view returns (uint256);



    /// @dev Returns the total amount staked tokens (excluding unstaked tokens).

    /// @return uint256 The total staked tokens of all stake owners.

    function getTotalStakedTokens() external view returns (uint256);



    /// @dev Returns the time that the cooldown period ends (or ended) and the amount of tokens to be released.

    /// @param _stakeOwner address The address to check.

    /// @return cooldownAmount uint256 The total tokens in cooldown.

    /// @return cooldownEndTime uint256 The time when the cooldown period ends (in seconds).

    function getUnstakeStatus(address _stakeOwner) external view returns (uint256 cooldownAmount,

        uint256 cooldownEndTime);



    /// @dev Migrates the stake of msg.sender from this staking contract to a new approved staking contract.

    /// @param _newStakingContract IMigratableStakingContract The new staking contract which supports stake migration.

    /// @param _amount uint256 The amount of tokens to migrate.

    function migrateStakedTokens(IMigratableStakingContract _newStakingContract, uint256 _amount) external;



    event Staked(address indexed stakeOwner, uint256 amount, uint256 totalStakedAmount);

    event Unstaked(address indexed stakeOwner, uint256 amount, uint256 totalStakedAmount);

    event Withdrew(address indexed stakeOwner, uint256 amount, uint256 totalStakedAmount);

    event Restaked(address indexed stakeOwner, uint256 amount, uint256 totalStakedAmount);

    event MigratedStake(address indexed stakeOwner, uint256 amount, uint256 totalStakedAmount);

}

interface IStakingRewards {



    event DelegatorStakingRewardsAssigned(address indexed delegator, uint256 amount, uint256 totalAwarded, address guardian, uint256 delegatorRewardsPerToken);

    event GuardianStakingRewardsAssigned(address indexed guardian, uint256 amount, uint256 totalAwarded, uint256 delegatorRewardsPerToken, uint256 stakingRewardsPerWeight);

    event StakingRewardsClaimed(address indexed addr, uint256 claimedDelegatorRewards, uint256 claimedGuardianRewards, uint256 totalClaimedDelegatorRewards, uint256 totalClaimedGuardianRewards);

    event StakingRewardsAllocated(uint256 allocatedRewards, uint256 stakingRewardsPerWeight);

    event GuardianDelegatorsStakingRewardsPercentMilleUpdated(address indexed guardian, uint256 delegatorsStakingRewardsPercentMille);



    /*

     * External functions

     */



    /// @dev Returns the currently unclaimed orbs token reward balance of the given address.

    function getStakingRewardsBalance(address addr) external view returns (uint256 balance);



    /// @dev Allows Guardian to set a different delegator staking reward cut than the default

    /// delegatorRewardsPercentMille accepts values between 0 - maxDelegatorsStakingRewardsPercentMille

    function setGuardianDelegatorsStakingRewardsPercentMille(uint32 delegatorRewardsPercentMille) external;



    /// @dev Returns the guardian's delegatorRewardsPercentMille

    function getGuardianDelegatorsStakingRewardsPercentMille(address guardian) external view returns (uint256 delegatorRewardsRatioPercentMille);



    /// @dev Claims the staking rewards balance of addr by staking

    function claimStakingRewards(address addr) external;



    /// @dev Returns the amount of ORBS tokens in the staking wallet that were allocated

    /// but not yet claimed. The staking wallet balance must always larger than the allocated value.

    function getStakingRewardsWalletAllocatedTokens() external view returns (uint256 allocated);



    function getGuardianStakingRewardsData(address guardian) external view returns (

        uint256 balance,

        uint256 claimed,

        uint256 delegatorRewardsPerToken,

        uint256 lastStakingRewardsPerWeight

    );



    function getDelegatorStakingRewardsData(address delegator) external view returns (

        uint256 balance,

        uint256 claimed,

        uint256 lastDelegatorRewardsPerToken

    );



    function getStakingRewardsState() external view returns (

        uint96 stakingRewardsPerWeight,

        uint96 unclaimedStakingRewards

    );



    function getCurrentStakingRewardsRatePercentMille() external returns (uint256);



    /// @dev called by the Committee contract upon expected change in the committee membership of the guardian

    /// Triggers update of the member rewards

    function committeeMembershipWillChange(address guardian, uint256 weight, uint256 totalCommitteeWeight, bool inCommittee, bool inCommitteeAfter) external /* onlyCommitteeContract */;



    /// @dev called by the Delegation contract upon expected change in a committee member delegator stake

    /// Triggers update of the delegator and guardian staking rewards

    function delegationWillChange(address guardian, uint256 delegatedStake, address delegator, uint256 delegatorStake, address nextGuardian, uint256 nextGuardianDelegatedStake) external /* onlyDelegationsContract */;



    /*

     * Governance functions

     */



    event AnnualStakingRewardsRateChanged(uint256 annualRateInPercentMille, uint256 annualCap);

    event DefaultDelegatorsStakingRewardsChanged(uint32 defaultDelegatorsStakingRewardsPercentMille);

    event MaxDelegatorsStakingRewardsChanged(uint32 maxDelegatorsStakingRewardsPercentMille);

    event RewardDistributionActivated(uint256 startTime);

    event RewardDistributionDeactivated();

    event StakingRewardsBalanceMigrated(address indexed addr, uint256 guardianStakingRewards, uint256 delegatorStakingRewards, address toRewardsContract);

    event StakingRewardsBalanceMigrationAccepted(address from, address indexed addr, uint256 guardianStakingRewards, uint256 delegatorStakingRewards);

    event EmergencyWithdrawal(address addr);



    /// @dev activates reward distribution, all rewards will be distributed up

    /// assuming the last assignment was on startTime (the time the old contarct was deactivated)

    function activateRewardDistribution(uint startTime) external /* onlyInitializationAdmin */;



    /// @dev deactivates reward distribution, all rewards will be distributed up

    /// deactivate moment.

    function deactivateRewardDistribution() external /* onlyMigrationManager */;



    /// @dev Sets the default cut of the delegators staking reward.

    function setDefaultDelegatorsStakingRewardsPercentMille(uint32 defaultDelegatorsStakingRewardsPercentMille) external /* onlyFunctionalManager onlyWhenActive */;



    function getDefaultDelegatorsStakingRewardsPercentMille() external view returns (uint32);



    /// @dev Sets the maximum cut of the delegators staking reward.

    function setMaxDelegatorsStakingRewardsPercentMille(uint32 maxDelegatorsStakingRewardsPercentMille) external /* onlyFunctionalManager onlyWhenActive */;



    function getMaxDelegatorsStakingRewardsPercentMille() external view returns (uint32);



    /// @dev Sets a new annual rate and cap for the staking reward.

    function setAnnualStakingRewardsRate(uint256 annualRateInPercentMille, uint256 annualCap) external /* onlyFunctionalManager */;



    function getAnnualStakingRewardsRatePercentMille() external view returns (uint32);



    function getAnnualStakingRewardsCap() external view returns (uint256);



    function isRewardAllocationActive() external view returns (bool);



    /// @dev Returns the contract's settings

    function getSettings() external view returns (

        uint annualStakingRewardsCap,

        uint32 annualStakingRewardsRatePercentMille,

        uint32 defaultDelegatorsStakingRewardsPercentMille,

        uint32 maxDelegatorsStakingRewardsPercentMille,

        bool rewardAllocationActive

    );



    /// @dev migrates the staking rewards balance of the guardian to the rewards contract as set in the registry.

    function migrateRewardsBalance(address guardian) external;



    /// @dev accepts guardian's balance migration from a previous rewards contarct.

    function acceptRewardsBalanceMigration(address guardian, uint256 guardianStakingRewards, uint256 delegatorStakingRewards) external;



    /// @dev emergency withdrawal of the rewards contract balances, may eb called only by the EmergencyManager. 

    function emergencyWithdraw() external /* onlyMigrationManager */;

}

contract Initializable {



    address private _initializationAdmin;



    event InitializationComplete();



    constructor() public{

        _initializationAdmin = msg.sender;

    }



    modifier onlyInitializationAdmin() {

        require(msg.sender == initializationAdmin(), "sender is not the initialization admin");



        _;

    }



    /*

    * External functions

    */



    function initializationAdmin() public view returns (address) {

        return _initializationAdmin;

    }



    function initializationComplete() external onlyInitializationAdmin {

        _initializationAdmin = address(0);

        emit InitializationComplete();

    }



    function isInitializationComplete() public view returns (bool) {

        return _initializationAdmin == address(0);

    }



}

library Math {

    /**

     * @dev Returns the largest of two numbers.

     */

    function max(uint256 a, uint256 b) internal pure returns (uint256) {

        return a >= b ? a : b;

    }



    /**

     * @dev Returns the smallest of two numbers.

     */

    function min(uint256 a, uint256 b) internal pure returns (uint256) {

        return a < b ? a : b;

    }



    /**

     * @dev Returns the average of two numbers. The result is rounded towards

     * zero.

     */

    function average(uint256 a, uint256 b) internal pure returns (uint256) {

        // (a + b) / 2 can overflow, so we distribute

        return (a / 2) + (b / 2) + ((a % 2 + b % 2) / 2);

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

library SafeMath96 {

    /**

     * @dev Returns the addition of two unsigned integers, reverting on

     * overflow.

     *

     * Counterpart to Solidity's `+` operator.

     *

     * Requirements:

     * - Addition cannot overflow.

     */

    function add(uint96 a, uint256 b) internal pure returns (uint96) {

        require(uint256(uint96(b)) == b, "SafeMath: addition overflow");

        uint96 c = a + uint96(b);

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

     * - Subtraction cannot overflow.

     */

    function sub(uint96 a, uint256 b) internal pure returns (uint96) {

        require(uint256(uint96(b)) == b, "SafeMath: subtraction overflow");

        return sub(a, uint96(b), "SafeMath: subtraction overflow");

    }



    /**

     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on

     * overflow (when the result is negative).

     *

     * Counterpart to Solidity's `-` operator.

     *

     * Requirements:

     * - Subtraction cannot overflow.

     *

     * _Available since v2.4.0._

     */

    function sub(uint96 a, uint96 b, string memory errorMessage) internal pure returns (uint96) {

        require(b <= a, errorMessage);

        uint96 c = a - b;



        return c;

    }



}

contract WithClaimableRegistryManagement is Context {

    address private _registryAdmin;

    address private _pendingRegistryAdmin;



    event RegistryManagementTransferred(address indexed previousRegistryAdmin, address indexed newRegistryAdmin);



    /**

     * @dev Initializes the contract setting the deployer as the initial registryRegistryAdmin.

     */

    constructor () internal {

        address msgSender = _msgSender();

        _registryAdmin = msgSender;

        emit RegistryManagementTransferred(address(0), msgSender);

    }



    /**

     * @dev Returns the address of the current registryAdmin.

     */

    function registryAdmin() public view returns (address) {

        return _registryAdmin;

    }



    /**

     * @dev Throws if called by any account other than the registryAdmin.

     */

    modifier onlyRegistryAdmin() {

        require(isRegistryAdmin(), "WithClaimableRegistryManagement: caller is not the registryAdmin");

        _;

    }



    /**

     * @dev Returns true if the caller is the current registryAdmin.

     */

    function isRegistryAdmin() public view returns (bool) {

        return _msgSender() == _registryAdmin;

    }



    /**

     * @dev Leaves the contract without registryAdmin. It will not be possible to call

     * `onlyManager` functions anymore. Can only be called by the current registryAdmin.

     *

     * NOTE: Renouncing registryManagement will leave the contract without an registryAdmin,

     * thereby removing any functionality that is only available to the registryAdmin.

     */

    function renounceRegistryManagement() public onlyRegistryAdmin {

        emit RegistryManagementTransferred(_registryAdmin, address(0));

        _registryAdmin = address(0);

    }



    /**

     * @dev Transfers registryManagement of the contract to a new account (`newManager`).

     */

    function _transferRegistryManagement(address newRegistryAdmin) internal {

        require(newRegistryAdmin != address(0), "RegistryAdmin: new registryAdmin is the zero address");

        emit RegistryManagementTransferred(_registryAdmin, newRegistryAdmin);

        _registryAdmin = newRegistryAdmin;

    }



    /**

     * @dev Modifier throws if called by any account other than the pendingManager.

     */

    modifier onlyPendingRegistryAdmin() {

        require(msg.sender == _pendingRegistryAdmin, "Caller is not the pending registryAdmin");

        _;

    }

    /**

     * @dev Allows the current registryAdmin to set the pendingManager address.

     * @param newRegistryAdmin The address to transfer registryManagement to.

     */

    function transferRegistryManagement(address newRegistryAdmin) public onlyRegistryAdmin {

        _pendingRegistryAdmin = newRegistryAdmin;

    }



    /**

     * @dev Allows the _pendingRegistryAdmin address to finalize the transfer.

     */

    function claimRegistryManagement() external onlyPendingRegistryAdmin {

        _transferRegistryManagement(_pendingRegistryAdmin);

        _pendingRegistryAdmin = address(0);

    }



    /**

     * @dev Returns the current pendingRegistryAdmin

    */

    function pendingRegistryAdmin() public view returns (address) {

       return _pendingRegistryAdmin;  

    }

}

contract ContractRegistryAccessor is WithClaimableRegistryManagement, Initializable {



    IContractRegistry private contractRegistry;



    constructor(IContractRegistry _contractRegistry, address _registryAdmin) public {

        require(address(_contractRegistry) != address(0), "_contractRegistry cannot be 0");

        setContractRegistry(_contractRegistry);

        _transferRegistryManagement(_registryAdmin);

    }



    modifier onlyAdmin {

        require(isAdmin(), "sender is not an admin (registryManger or initializationAdmin)");



        _;

    }



    function isManager(string memory role) internal view returns (bool) {

        IContractRegistry _contractRegistry = contractRegistry;

        return isAdmin() || _contractRegistry != IContractRegistry(0) && contractRegistry.getManager(role) == msg.sender;

    }



    function isAdmin() internal view returns (bool) {

        return msg.sender == registryAdmin() || msg.sender == initializationAdmin() || msg.sender == address(contractRegistry);

    }



    function getProtocolContract() internal view returns (address) {

        return contractRegistry.getContract("protocol");

    }



    function getStakingRewardsContract() internal view returns (address) {

        return contractRegistry.getContract("stakingRewards");

    }



    function getFeesAndBootstrapRewardsContract() internal view returns (address) {

        return contractRegistry.getContract("feesAndBootstrapRewards");

    }



    function getCommitteeContract() internal view returns (address) {

        return contractRegistry.getContract("committee");

    }



    function getElectionsContract() internal view returns (address) {

        return contractRegistry.getContract("elections");

    }



    function getDelegationsContract() internal view returns (address) {

        return contractRegistry.getContract("delegations");

    }



    function getGuardiansRegistrationContract() internal view returns (address) {

        return contractRegistry.getContract("guardiansRegistration");

    }



    function getCertificationContract() internal view returns (address) {

        return contractRegistry.getContract("certification");

    }



    function getStakingContract() internal view returns (address) {

        return contractRegistry.getContract("staking");

    }



    function getSubscriptionsContract() internal view returns (address) {

        return contractRegistry.getContract("subscriptions");

    }



    function getStakingRewardsWallet() internal view returns (address) {

        return contractRegistry.getContract("stakingRewardsWallet");

    }



    function getBootstrapRewardsWallet() internal view returns (address) {

        return contractRegistry.getContract("bootstrapRewardsWallet");

    }



    function getGeneralFeesWallet() internal view returns (address) {

        return contractRegistry.getContract("generalFeesWallet");

    }



    function getCertifiedFeesWallet() internal view returns (address) {

        return contractRegistry.getContract("certifiedFeesWallet");

    }



    function getStakingContractHandler() internal view returns (address) {

        return contractRegistry.getContract("stakingContractHandler");

    }



    /*

    * Governance functions

    */



    event ContractRegistryAddressUpdated(address addr);



    function setContractRegistry(IContractRegistry newContractRegistry) public onlyAdmin {

        require(newContractRegistry.getPreviousContractRegistry() == address(contractRegistry), "new contract registry must provide the previous contract registry");

        contractRegistry = newContractRegistry;

        emit ContractRegistryAddressUpdated(address(newContractRegistry));

    }



    function getContractRegistry() public view returns (IContractRegistry) {

        return contractRegistry;

    }



}

contract Lockable is ILockable, ContractRegistryAccessor {



    bool public locked;



    constructor(IContractRegistry _contractRegistry, address _registryAdmin) ContractRegistryAccessor(_contractRegistry, _registryAdmin) public {}



    modifier onlyLockOwner() {

        require(msg.sender == registryAdmin() || msg.sender == address(getContractRegistry()), "caller is not a lock owner");



        _;

    }



    function lock() external override onlyLockOwner {

        locked = true;

        emit Locked();

    }



    function unlock() external override onlyLockOwner {

        locked = false;

        emit Unlocked();

    }



    function isLocked() external override view returns (bool) {

        return locked;

    }



    modifier onlyWhenActive() {

        require(!locked, "contract is locked for this operation");



        _;

    }

}

contract ManagedContract is Lockable {



    constructor(IContractRegistry _contractRegistry, address _registryAdmin) Lockable(_contractRegistry, _registryAdmin) public {}



    modifier onlyMigrationManager {

        require(isManager("migrationManager"), "sender is not the migration manager");



        _;

    }



    modifier onlyFunctionalManager {

        require(isManager("functionalManager"), "sender is not the functional manager");



        _;

    }



    function refreshContracts() virtual external {}



}

contract StakingRewards is IStakingRewards, ManagedContract {

    using SafeMath for uint256;

    using SafeMath96 for uint96;



    uint256 constant PERCENT_MILLIE_BASE = 100000;

    uint256 constant TOKEN_BASE = 1e18;



    struct Settings {

        uint96 annualCap;

        uint32 annualRateInPercentMille;

        uint32 defaultDelegatorsStakingRewardsPercentMille;

        uint32 maxDelegatorsStakingRewardsPercentMille;

        bool rewardAllocationActive;

    }

    Settings settings;



    IERC20 public erc20;



    struct StakingRewardsState {

        uint96 stakingRewardsPerWeight;

        uint96 unclaimedStakingRewards;

        uint32 lastAssigned;

    }

    StakingRewardsState public stakingRewardsState;



    uint256 public stakingRewardsWithdrawnFromWallet;



    struct GuardianStakingRewards {

        uint96 delegatorRewardsPerToken;

        uint96 lastStakingRewardsPerWeight;

        uint96 balance;

        uint96 claimed;

    }

    mapping(address => GuardianStakingRewards) public guardiansStakingRewards;



    struct GuardianRewardSettings {

        uint32 delegatorsStakingRewardsPercentMille;

        bool overrideDefault;

    }

    mapping(address => GuardianRewardSettings) public guardiansRewardSettings;



    struct DelegatorStakingRewards {

        uint96 balance;

        uint96 lastDelegatorRewardsPerToken;

        uint96 claimed;

    }

    mapping(address => DelegatorStakingRewards) public delegatorsStakingRewards;



    constructor(

        IContractRegistry _contractRegistry,

        address _registryAdmin,

        IERC20 _erc20,

        uint annualRateInPercentMille,

        uint annualCap,

        uint32 defaultDelegatorsStakingRewardsPercentMille,

        uint32 maxDelegatorsStakingRewardsPercentMille,

        IStakingRewards previousRewardsContract,

        address[] memory guardiansToMigrate

    ) ManagedContract(_contractRegistry, _registryAdmin) public {

        require(address(_erc20) != address(0), "erc20 must not be 0");



        _setAnnualStakingRewardsRate(annualRateInPercentMille, annualCap);

        setMaxDelegatorsStakingRewardsPercentMille(maxDelegatorsStakingRewardsPercentMille);

        setDefaultDelegatorsStakingRewardsPercentMille(defaultDelegatorsStakingRewardsPercentMille);



        erc20 = _erc20;



        if (address(previousRewardsContract) != address(0)) {

            migrateGuardiansSettings(previousRewardsContract, guardiansToMigrate);

        }

    }



    modifier onlyCommitteeContract() {

        require(msg.sender == address(committeeContract), "caller is not the elections contract");



        _;

    }



    modifier onlyDelegationsContract() {

        require(msg.sender == address(delegationsContract), "caller is not the delegations contract");



        _;

    }



    /*

    * External functions

    */



    function committeeMembershipWillChange(address guardian, uint256 weight, uint256 totalCommitteeWeight, bool inCommittee, bool inCommitteeAfter) external override onlyWhenActive onlyCommitteeContract {

        uint256 delegatedStake = delegationsContract.getDelegatedStake(guardian);



        Settings memory _settings = settings;

        StakingRewardsState memory _stakingRewardsState = _updateStakingRewardsState(totalCommitteeWeight, _settings);

        _updateGuardianStakingRewards(guardian, inCommittee, inCommitteeAfter, weight, delegatedStake, _stakingRewardsState, _settings);

    }



    function delegationWillChange(address guardian, uint256 guardianDelegatedStake, address delegator, uint256 delegatorStake, address nextGuardian, uint256 nextGuardianDelegatedStake) external override onlyWhenActive onlyDelegationsContract {

        Settings memory _settings = settings;

        (bool inCommittee, uint256 weight, , uint256 totalCommitteeWeight) = committeeContract.getMemberInfo(guardian);



        StakingRewardsState memory _stakingRewardsState = _updateStakingRewardsState(totalCommitteeWeight, _settings);

        GuardianStakingRewards memory guardianStakingRewards = _updateGuardianStakingRewards(guardian, inCommittee, inCommittee, weight, guardianDelegatedStake, _stakingRewardsState, _settings);

        _updateDelegatorStakingRewards(delegator, delegatorStake, guardian, guardianStakingRewards);



        if (nextGuardian != guardian) {

            (inCommittee, weight, , totalCommitteeWeight) = committeeContract.getMemberInfo(nextGuardian);

            GuardianStakingRewards memory nextGuardianStakingRewards = _updateGuardianStakingRewards(nextGuardian, inCommittee, inCommittee, weight, nextGuardianDelegatedStake, _stakingRewardsState, _settings);

            delegatorsStakingRewards[delegator].lastDelegatorRewardsPerToken = nextGuardianStakingRewards.delegatorRewardsPerToken;

        }

    }



    function getStakingRewardsBalance(address addr) external override view returns (uint256) {

        DelegatorStakingRewards memory delegatorStakingRewards = getDelegatorStakingRewards(addr);

        GuardianStakingRewards memory guardianStakingRewards = getGuardianStakingRewards(addr); // TODO consider removing, data in state must be up to date at this point

        return delegatorStakingRewards.balance.add(guardianStakingRewards.balance);

    }



    function claimStakingRewards(address addr) external override onlyWhenActive {

        (uint256 guardianRewards, uint256 delegatorRewards) = claimStakingRewardsLocally(addr);



        uint96 claimedGuardianRewards = guardiansStakingRewards[addr].claimed.add(guardianRewards);

        guardiansStakingRewards[addr].claimed = claimedGuardianRewards;

        uint96 claimedDelegatorRewards = delegatorsStakingRewards[addr].claimed.add(delegatorRewards);

        delegatorsStakingRewards[addr].claimed = claimedDelegatorRewards;



        uint256 total = delegatorRewards.add(guardianRewards);



        require(erc20.approve(address(stakingContract), total), "claimStakingRewards: approve failed");



        address[] memory addrs = new address[](1);

        addrs[0] = addr;

        uint256[] memory amounts = new uint256[](1);

        amounts[0] = total;

        stakingContract.distributeRewards(total, addrs, amounts);



        emit StakingRewardsClaimed(addr, delegatorRewards, guardianRewards, claimedDelegatorRewards, claimedGuardianRewards);

    }



    function getGuardianStakingRewardsData(address guardian) external override view returns (

        uint256 balance,

        uint256 claimed,

        uint256 delegatorRewardsPerToken,

        uint256 lastStakingRewardsPerWeight

    ) {

        GuardianStakingRewards memory rewards = getGuardianStakingRewards(guardian);

        return (rewards.balance, rewards.claimed, rewards.delegatorRewardsPerToken, rewards.lastStakingRewardsPerWeight);

    }



    function getDelegatorStakingRewardsData(address delegator) external override view returns (

        uint256 balance,

        uint256 claimed,

        uint256 lastDelegatorRewardsPerToken

    ) {

        DelegatorStakingRewards memory rewards = getDelegatorStakingRewards(delegator);

        return (rewards.balance, rewards.claimed, rewards.lastDelegatorRewardsPerToken);

    }



    function getStakingRewardsState() public override view returns (

        uint96 stakingRewardsPerWeight,

        uint96 unclaimedStakingRewards

    ) {

        (, , uint totalCommitteeWeight) = committeeContract.getCommitteeStats();

        (StakingRewardsState memory _stakingRewardsState,) = _getStakingRewardsState(totalCommitteeWeight, settings);

        stakingRewardsPerWeight = _stakingRewardsState.stakingRewardsPerWeight;

        unclaimedStakingRewards = _stakingRewardsState.unclaimedStakingRewards;

    }



    function getCurrentStakingRewardsRatePercentMille() external override returns (uint256) {

        (, , uint totalCommitteeWeight) = committeeContract.getCommitteeStats();

        return _getAnnualRate(totalCommitteeWeight, settings);

    }



    function setGuardianDelegatorsStakingRewardsPercentMille(uint32 delegatorRewardsPercentMille) external override onlyWhenActive {

        require(delegatorRewardsPercentMille <= PERCENT_MILLIE_BASE, "delegatorRewardsPercentMille must be 100000 at most");

        require(delegatorRewardsPercentMille <= settings.maxDelegatorsStakingRewardsPercentMille, "delegatorRewardsPercentMille must not be larger than maxDelegatorsStakingRewardsPercentMille");

        updateDelegatorStakingRewards(msg.sender);

        _setGuardianDelegatorsStakingRewardsPercentMille(msg.sender, delegatorRewardsPercentMille);

    }



    function getGuardianDelegatorsStakingRewardsPercentMille(address guardian) external override view returns (uint256 delegatorRewardsRatioPercentMille) {

        return _getGuardianDelegatorsStakingRewardsPercentMille(guardian, settings);

    }



    function getStakingRewardsWalletAllocatedTokens() external override view returns (uint256 allocated) {

        (, uint96 unclaimedStakingRewards) = getStakingRewardsState();

        return uint256(unclaimedStakingRewards).sub(stakingRewardsWithdrawnFromWallet);

    }



    /*

    * Governance functions

    */



    function migrateRewardsBalance(address addr) external override {

        require(!settings.rewardAllocationActive, "Reward distribution must be deactivated for migration");



        IStakingRewards currentRewardsContract = IStakingRewards(getStakingRewardsContract());

        require(address(currentRewardsContract) != address(this), "New rewards contract is not set");



        (uint256 guardianRewards, uint256 delegatorRewards) = claimStakingRewardsLocally(addr);



        require(erc20.approve(address(currentRewardsContract), guardianRewards.add(delegatorRewards)), "migrateRewardsBalance: approve failed");

        currentRewardsContract.acceptRewardsBalanceMigration(addr, guardianRewards, delegatorRewards);



        emit StakingRewardsBalanceMigrated(addr, guardianRewards, delegatorRewards, address(currentRewardsContract));

    }



    function acceptRewardsBalanceMigration(address addr, uint256 guardianStakingRewards, uint256 delegatorStakingRewards) external override {

        guardiansStakingRewards[addr].balance = guardiansStakingRewards[addr].balance.add(guardianStakingRewards);

        delegatorsStakingRewards[addr].balance = delegatorsStakingRewards[addr].balance.add(delegatorStakingRewards);



        uint orbsTransferAmount = guardianStakingRewards.add(delegatorStakingRewards);

        if (orbsTransferAmount > 0) {

            require(erc20.transferFrom(msg.sender, address(this), orbsTransferAmount), "acceptRewardBalanceMigration: transfer failed");

        }



        emit StakingRewardsBalanceMigrationAccepted(msg.sender, addr, guardianStakingRewards, delegatorStakingRewards);

    }



    function emergencyWithdraw() external override onlyMigrationManager {

        emit EmergencyWithdrawal(msg.sender);

        require(erc20.transfer(msg.sender, erc20.balanceOf(address(this))), "Rewards::emergencyWithdraw - transfer failed (orbs token)");

    }



    function activateRewardDistribution(uint startTime) external override onlyMigrationManager {

        stakingRewardsState.lastAssigned = uint32(startTime);

        settings.rewardAllocationActive = true;



        emit RewardDistributionActivated(startTime);

    }



    function deactivateRewardDistribution() external override onlyMigrationManager {

        require(settings.rewardAllocationActive, "reward distribution is already deactivated");



        updateStakingRewardsState();



        settings.rewardAllocationActive = false;



        emit RewardDistributionDeactivated();

    }



    function setDefaultDelegatorsStakingRewardsPercentMille(uint32 defaultDelegatorsStakingRewardsPercentMille) public override onlyFunctionalManager {

        require(defaultDelegatorsStakingRewardsPercentMille <= PERCENT_MILLIE_BASE, "defaultDelegatorsStakingRewardsPercentMille must not be larger than 100000");

        require(defaultDelegatorsStakingRewardsPercentMille <= settings.maxDelegatorsStakingRewardsPercentMille, "defaultDelegatorsStakingRewardsPercentMille must not be larger than maxDelegatorsStakingRewardsPercentMille");

        settings.defaultDelegatorsStakingRewardsPercentMille = defaultDelegatorsStakingRewardsPercentMille;

        emit DefaultDelegatorsStakingRewardsChanged(defaultDelegatorsStakingRewardsPercentMille);

    }



    function getDefaultDelegatorsStakingRewardsPercentMille() public override view returns (uint32) {

        return settings.defaultDelegatorsStakingRewardsPercentMille;

    }



    function setMaxDelegatorsStakingRewardsPercentMille(uint32 maxDelegatorsStakingRewardsPercentMille) public override onlyFunctionalManager {

        require(maxDelegatorsStakingRewardsPercentMille <= PERCENT_MILLIE_BASE, "maxDelegatorsStakingRewardsPercentMille must not be larger than 100000");

        settings.maxDelegatorsStakingRewardsPercentMille = maxDelegatorsStakingRewardsPercentMille;

        emit MaxDelegatorsStakingRewardsChanged(maxDelegatorsStakingRewardsPercentMille);

    }



    function getMaxDelegatorsStakingRewardsPercentMille() public override view returns (uint32) {

        return settings.maxDelegatorsStakingRewardsPercentMille;

    }



    function setAnnualStakingRewardsRate(uint256 annualRateInPercentMille, uint256 annualCap) external override onlyFunctionalManager {

        updateStakingRewardsState();

        return _setAnnualStakingRewardsRate(annualRateInPercentMille, annualCap);

    }



    function getAnnualStakingRewardsRatePercentMille() external override view returns (uint32) {

        return settings.annualRateInPercentMille;

    }



    function getAnnualStakingRewardsCap() external override view returns (uint256) {

        return settings.annualCap;

    }



    function isRewardAllocationActive() external override view returns (bool) {

        return settings.rewardAllocationActive;

    }



    function getSettings() external override view returns (

        uint annualStakingRewardsCap,

        uint32 annualStakingRewardsRatePercentMille,

        uint32 defaultDelegatorsStakingRewardsPercentMille,

        uint32 maxDelegatorsStakingRewardsPercentMille,

        bool rewardAllocationActive

    ) {

        Settings memory _settings = settings;

        annualStakingRewardsCap = _settings.annualCap;

        annualStakingRewardsRatePercentMille = _settings.annualRateInPercentMille;

        defaultDelegatorsStakingRewardsPercentMille = _settings.defaultDelegatorsStakingRewardsPercentMille;

        maxDelegatorsStakingRewardsPercentMille = _settings.maxDelegatorsStakingRewardsPercentMille;

        rewardAllocationActive = _settings.rewardAllocationActive;

    }



    /*

    * Private functions

    */



    // Global state



    function _getAnnualRate(uint256 totalCommitteeWeight, Settings memory _settings) private pure returns (uint256) {

        return totalCommitteeWeight == 0 ? 0 : Math.min(uint(_settings.annualRateInPercentMille), uint256(_settings.annualCap).mul(PERCENT_MILLIE_BASE).div(totalCommitteeWeight));

    }



    function calcStakingRewardPerWeightDelta(uint256 totalCommitteeWeight, uint duration, Settings memory _settings) private pure returns (uint256 stakingRewardsPerTokenDelta) {

        stakingRewardsPerTokenDelta = 0;



        if (totalCommitteeWeight > 0) {

            uint annualRateInPercentMille = _getAnnualRate(totalCommitteeWeight, _settings);

            stakingRewardsPerTokenDelta = annualRateInPercentMille.mul(TOKEN_BASE).mul(duration).div(PERCENT_MILLIE_BASE.mul(365 days));

        }

    }



    function _getStakingRewardsState(uint256 totalCommitteeWeight, Settings memory _settings) private view returns (StakingRewardsState memory _stakingRewardsState, uint256 allocatedRewards) {

        _stakingRewardsState = stakingRewardsState;

        if (_settings.rewardAllocationActive) {

            uint delta = calcStakingRewardPerWeightDelta(totalCommitteeWeight, block.timestamp.sub(stakingRewardsState.lastAssigned), _settings);

            _stakingRewardsState.stakingRewardsPerWeight = stakingRewardsState.stakingRewardsPerWeight.add(delta);

            _stakingRewardsState.lastAssigned = uint32(block.timestamp);

            allocatedRewards = delta.mul(totalCommitteeWeight).div(TOKEN_BASE);

            _stakingRewardsState.unclaimedStakingRewards = _stakingRewardsState.unclaimedStakingRewards.add(allocatedRewards);

        }

    }



    function _updateStakingRewardsState(uint256 totalCommitteeWeight, Settings memory _settings) private returns (StakingRewardsState memory _stakingRewardsState) {

        if (!_settings.rewardAllocationActive) {

            return stakingRewardsState;

        }



        uint allocatedRewards;

        (_stakingRewardsState, allocatedRewards) = _getStakingRewardsState(totalCommitteeWeight, _settings);

        stakingRewardsState = _stakingRewardsState;

        emit StakingRewardsAllocated(allocatedRewards, _stakingRewardsState.stakingRewardsPerWeight);

    }



    function updateStakingRewardsState() private returns (StakingRewardsState memory _stakingRewardsState) {

        (, , uint totalCommitteeWeight) = committeeContract.getCommitteeStats();

        return _updateStakingRewardsState(totalCommitteeWeight, settings);

    }



    // Guardian state



    function _getGuardianStakingRewards(address guardian, bool inCommittee, bool inCommitteeAfter, uint256 guardianWeight, uint256 guardianDelegatedStake, StakingRewardsState memory _stakingRewardsState, Settings memory _settings) private view returns (GuardianStakingRewards memory guardianStakingRewards, uint256 rewardsAdded) {

        guardianStakingRewards = guardiansStakingRewards[guardian];



        if (inCommittee) {

            uint256 totalRewards = uint256(_stakingRewardsState.stakingRewardsPerWeight)

                .sub(guardianStakingRewards.lastStakingRewardsPerWeight)

                .mul(guardianWeight);



            uint256 delegatorRewardsRatioPercentMille = _getGuardianDelegatorsStakingRewardsPercentMille(guardian, _settings);



            uint256 delegatorRewardsPerTokenDelta = guardianDelegatedStake == 0 ? 0 : totalRewards

                .div(guardianDelegatedStake)

                .mul(delegatorRewardsRatioPercentMille)

                .div(PERCENT_MILLIE_BASE);



            uint256 guardianCutPercentMille = PERCENT_MILLIE_BASE.sub(delegatorRewardsRatioPercentMille);



            rewardsAdded = totalRewards

                    .mul(guardianCutPercentMille)

                    .div(PERCENT_MILLIE_BASE)

                    .div(TOKEN_BASE);



            guardianStakingRewards.delegatorRewardsPerToken = guardianStakingRewards.delegatorRewardsPerToken.add(delegatorRewardsPerTokenDelta);

            guardianStakingRewards.balance = guardianStakingRewards.balance.add(rewardsAdded);

        }



        guardianStakingRewards.lastStakingRewardsPerWeight = inCommitteeAfter ? _stakingRewardsState.stakingRewardsPerWeight : 0;

    }



    function getGuardianStakingRewards(address guardian) private view returns (GuardianStakingRewards memory guardianStakingRewards) {

        Settings memory _settings = settings;



        (bool inCommittee, uint256 guardianWeight, ,uint256 totalCommitteeWeight) = committeeContract.getMemberInfo(guardian);

        uint256 guardianDelegatedStake = delegationsContract.getDelegatedStake(guardian);



        (StakingRewardsState memory _stakingRewardsState,) = _getStakingRewardsState(totalCommitteeWeight, _settings);

        (guardianStakingRewards,) = _getGuardianStakingRewards(guardian, inCommittee, inCommittee, guardianWeight, guardianDelegatedStake, _stakingRewardsState, _settings);

    }



    function _updateGuardianStakingRewards(address guardian, bool inCommittee, bool inCommitteeAfter, uint256 guardianWeight, uint256 guardianDelegatedStake, StakingRewardsState memory _stakingRewardsState, Settings memory _settings) private returns (GuardianStakingRewards memory guardianStakingRewards) {

        uint256 guardianStakingRewardsAdded;

        (guardianStakingRewards, guardianStakingRewardsAdded) = _getGuardianStakingRewards(guardian, inCommittee, inCommitteeAfter, guardianWeight, guardianDelegatedStake, _stakingRewardsState, _settings);

        guardiansStakingRewards[guardian] = guardianStakingRewards;

        emit GuardianStakingRewardsAssigned(guardian, guardianStakingRewardsAdded, guardianStakingRewards.claimed.add(guardianStakingRewards.balance), guardianStakingRewards.delegatorRewardsPerToken, _stakingRewardsState.stakingRewardsPerWeight);

    }



    function updateGuardianStakingRewards(address guardian, StakingRewardsState memory _stakingRewardsState, Settings memory _settings) private returns (GuardianStakingRewards memory guardianStakingRewards) {

        (bool inCommittee, uint256 guardianWeight,,) = committeeContract.getMemberInfo(guardian);

        return _updateGuardianStakingRewards(guardian, inCommittee, inCommittee, guardianWeight, delegationsContract.getDelegatedStake(guardian), _stakingRewardsState, _settings);

    }



    // Delegator state



    function _getDelegatorStakingRewards(address delegator, uint256 delegatorStake, GuardianStakingRewards memory guardianStakingRewards) private view returns (DelegatorStakingRewards memory delegatorStakingRewards, uint256 delegatorRewardsAdded) {

        delegatorStakingRewards = delegatorsStakingRewards[delegator];



        delegatorRewardsAdded = uint256(guardianStakingRewards.delegatorRewardsPerToken)

                .sub(delegatorStakingRewards.lastDelegatorRewardsPerToken)

                .mul(delegatorStake)

                .div(TOKEN_BASE);



        delegatorStakingRewards.balance = delegatorStakingRewards.balance.add(delegatorRewardsAdded);

        delegatorStakingRewards.lastDelegatorRewardsPerToken = guardianStakingRewards.delegatorRewardsPerToken;

    }



    function getDelegatorStakingRewards(address delegator) private view returns (DelegatorStakingRewards memory delegatorStakingRewards) {

        (address guardian, uint256 delegatorStake) = delegationsContract.getDelegationInfo(delegator);

        GuardianStakingRewards memory guardianStakingRewards = getGuardianStakingRewards(guardian);



        (delegatorStakingRewards,) = _getDelegatorStakingRewards(delegator, delegatorStake, guardianStakingRewards);

    }



    function _updateDelegatorStakingRewards(address delegator, uint256 delegatorStake, address guardian, GuardianStakingRewards memory guardianStakingRewards) private {

        uint256 delegatorStakingRewardsAdded;

        DelegatorStakingRewards memory delegatorStakingRewards;

        (delegatorStakingRewards, delegatorStakingRewardsAdded) = _getDelegatorStakingRewards(delegator, delegatorStake, guardianStakingRewards);

        delegatorsStakingRewards[delegator] = delegatorStakingRewards;



        emit DelegatorStakingRewardsAssigned(delegator, delegatorStakingRewardsAdded, delegatorStakingRewards.claimed.add(delegatorStakingRewards.balance), guardian, guardianStakingRewards.delegatorRewardsPerToken);

    }



    function updateDelegatorStakingRewards(address delegator) private {

        Settings memory _settings = settings;



        (, , uint totalCommitteeWeight) = committeeContract.getCommitteeStats();

        StakingRewardsState memory _stakingRewardsState = _updateStakingRewardsState(totalCommitteeWeight, _settings);



        (address guardian, uint delegatorStake) = delegationsContract.getDelegationInfo(delegator);

        GuardianStakingRewards memory guardianRewards = updateGuardianStakingRewards(guardian, _stakingRewardsState, _settings);



        _updateDelegatorStakingRewards(delegator, delegatorStake, guardian, guardianRewards);

    }



    // Guardian settings



    function _getGuardianDelegatorsStakingRewardsPercentMille(address guardian, Settings memory _settings) private view returns (uint256 delegatorRewardsRatioPercentMille) {

        GuardianRewardSettings memory guardianSettings = guardiansRewardSettings[guardian];

        delegatorRewardsRatioPercentMille =  guardianSettings.overrideDefault ? guardianSettings.delegatorsStakingRewardsPercentMille : _settings.defaultDelegatorsStakingRewardsPercentMille;

        return Math.min(delegatorRewardsRatioPercentMille, _settings.maxDelegatorsStakingRewardsPercentMille);

    }



    function migrateGuardiansSettings(IStakingRewards previousRewardsContract, address[] memory guardiansToMigrate) private {

        for (uint i = 0; i < guardiansToMigrate.length; i++) {

            _setGuardianDelegatorsStakingRewardsPercentMille(guardiansToMigrate[i], uint32(previousRewardsContract.getGuardianDelegatorsStakingRewardsPercentMille(guardiansToMigrate[i])));

        }

    }



    // Governance and misc.



    function _setAnnualStakingRewardsRate(uint256 annualRateInPercentMille, uint256 annualCap) private {

        require(uint256(uint96(annualCap)) == annualCap, "annualCap must fit in uint96");



        Settings memory _settings = settings;

        _settings.annualRateInPercentMille = uint32(annualRateInPercentMille);

        _settings.annualCap = uint96(annualCap);

        settings = _settings;



        emit AnnualStakingRewardsRateChanged(annualRateInPercentMille, annualCap);

    }



    function _setGuardianDelegatorsStakingRewardsPercentMille(address guardian, uint32 delegatorRewardsPercentMille) private {

        guardiansRewardSettings[guardian] = GuardianRewardSettings({

            overrideDefault: true,

            delegatorsStakingRewardsPercentMille: delegatorRewardsPercentMille

            });



        emit GuardianDelegatorsStakingRewardsPercentMilleUpdated(guardian, delegatorRewardsPercentMille);

    }



    function claimStakingRewardsLocally(address addr) private returns (uint256 guardianRewards, uint256 delegatorRewards) {

        updateDelegatorStakingRewards(addr);



        guardianRewards = guardiansStakingRewards[addr].balance;

        guardiansStakingRewards[addr].balance = 0;



        delegatorRewards = delegatorsStakingRewards[addr].balance;

        delegatorsStakingRewards[addr].balance = 0;



        uint256 total = delegatorRewards.add(guardianRewards);



        StakingRewardsState memory _stakingRewardsState = stakingRewardsState;



        uint256 _stakingRewardsWithdrawnFromWallet = stakingRewardsWithdrawnFromWallet;

        if (total > _stakingRewardsWithdrawnFromWallet) {

            uint256 allocated = _stakingRewardsState.unclaimedStakingRewards.sub(_stakingRewardsWithdrawnFromWallet);

            stakingRewardsWallet.withdraw(allocated);

            _stakingRewardsWithdrawnFromWallet = _stakingRewardsWithdrawnFromWallet.add(allocated);

        }



        stakingRewardsWithdrawnFromWallet = _stakingRewardsWithdrawnFromWallet.sub(total);

        stakingRewardsState.unclaimedStakingRewards = _stakingRewardsState.unclaimedStakingRewards.sub(total);

    }



    /*

     * Contracts topology / registry interface

     */



    ICommittee committeeContract;

    IDelegations delegationsContract;

    IProtocolWallet stakingRewardsWallet;

    IStakingContract stakingContract;

    function refreshContracts() external override {

        committeeContract = ICommittee(getCommitteeContract());

        delegationsContract = IDelegations(getDelegationsContract());

        stakingRewardsWallet = IProtocolWallet(getStakingRewardsWallet());

        stakingContract = IStakingContract(getStakingContract());

    }

}
