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

interface IFeesAndBootstrapRewards {

    event FeesAssigned(address indexed guardian, uint256 amount);

    event FeesWithdrawn(address indexed guardian, uint256 amount);

    event BootstrapRewardsAssigned(address indexed guardian, uint256 amount);

    event BootstrapRewardsWithdrawn(address indexed guardian, uint256 amount);



    /*

    * External functions

    */



    /// @dev called by the Committee contract upon expected change in the committee membership of the guardian

    /// Triggers update of the member rewards

    function committeeMembershipWillChange(address guardian, bool inCommittee, bool isCertified, bool nextCertification, uint generalCommitteeSize, uint certifiedCommitteeSize) external /* onlyCommitteeContract */;



    function getFeesAndBootstrapBalance(address guardian) external view returns (

        uint256 feeBalance,

        uint256 bootstrapBalance

    );



    /// @dev Transfer all of msg.sender's outstanding balance to their account

    function withdrawFees(address guardian) external;



    /// @dev Transfer all of msg.sender's outstanding balance to their account

    function withdrawBootstrapFunds(address guardian) external;



    /// @dev Returns the global Fees and Bootstrap rewards state 

    function getFeesAndBootstrapState() external view returns (

        uint256 certifiedFeesPerMember,

        uint256 generalFeesPerMember,

        uint256 certifiedBootstrapPerMember,

        uint256 generalBootstrapPerMember,

        uint256 lastAssigned

    );



    function getFeesAndBootstrapData(address guardian) external view returns (

        uint256 feeBalance,

        uint256 lastFeesPerMember,

        uint256 bootstrapBalance,

        uint256 lastBootstrapPerMember

    );



    /*

     * Governance

     */



    event GeneralCommitteeAnnualBootstrapChanged(uint256 generalCommitteeAnnualBootstrap);

    event CertifiedCommitteeAnnualBootstrapChanged(uint256 certifiedCommitteeAnnualBootstrap);

    event RewardDistributionActivated(uint256 startTime);

    event RewardDistributionDeactivated();

    event FeesAndBootstrapRewardsBalanceMigrated(address indexed guardian, uint256 fees, uint256 bootstrapRewards, address toRewardsContract);

    event FeesAndBootstrapRewardsBalanceMigrationAccepted(address from, address indexed guardian, uint256 fees, uint256 bootstrapRewards);

    event EmergencyWithdrawal(address addr);



    /// @dev deactivates reward distribution, all rewards will be distributed up

    /// deactivate moment.

    function deactivateRewardDistribution() external /* onlyMigrationManager */;



    /// @dev activates reward distribution, all rewards will be distributed up

    /// assuming the last assignment was on startTime (the time the old contarct was deactivated)

    function activateRewardDistribution(uint startTime) external /* onlyInitializationAdmin */;



    /// @dev Returns the contract's settings

    function getSettings() external view returns (

        uint generalCommitteeAnnualBootstrap,

        uint certifiedCommitteeAnnualBootstrap,

        bool rewardAllocationActive

    );



    function getGeneralCommitteeAnnualBootstrap() external view returns (uint256);



    /// @dev Assigns rewards and sets a new monthly rate for the geenral commitee bootstrap.

    function setGeneralCommitteeAnnualBootstrap(uint256 annual_amount) external /* onlyFunctionalManager */;



    function getCertifiedCommitteeAnnualBootstrap() external view returns (uint256);



    /// @dev Assigns rewards and sets a new monthly rate for the certification commitee bootstrap.

    function setCertifiedCommitteeAnnualBootstrap(uint256 annual_amount) external /* onlyFunctionalManager */;



    function isRewardAllocationActive() external view returns (bool);



    /// @dev migrates the staking rewards balance of the guardian to the rewards contract as set in the registry.

    function migrateRewardsBalance(address guardian) external;



    /// @dev accepts guardian's balance migration from a previous rewards contarct.

    function acceptRewardsBalanceMigration(address guardian, uint256 fees, uint256 bootstrapRewards) external;



    /// @dev emergency withdrawal of the rewards contract balances, may eb called only by the EmergencyManager. 

    function emergencyWithdraw() external; /* onlyMigrationManager */

}

interface IFeesWallet {



    event FeesWithdrawnFromBucket(uint256 bucketId, uint256 withdrawn, uint256 total);

    event FeesAddedToBucket(uint256 bucketId, uint256 added, uint256 total);



    /*

     *   External methods

     */



    /// @dev Called by: subscriptions contract.

    /// Top-ups the fee pool with the given amount at the given rate (typically called by the subscriptions contract).

    function fillFeeBuckets(uint256 amount, uint256 monthlyRate, uint256 fromTimestamp) external;



    /// @dev collect fees from the buckets since the last call and transfers the amount back.

    /// Called by: only Rewards contract.

    function collectFees() external returns (uint256 collectedFees) /* onlyRewardsContract */;



    /// @dev Returns the amount of fees that are currently available for withdrawal

    function getOutstandingFees() external view returns (uint256 outstandingFees);



    /*

     * General governance

     */



    event EmergencyWithdrawal(address addr);



    /// @dev migrates the fees of bucket starting at startTimestamp.

    /// bucketStartTime must be a bucket's start time.

    /// Calls acceptBucketMigration in the destination contract.

    function migrateBucket(IMigratableFeesWallet destination, uint256 bucketStartTime) external /* onlyMigrationManager */;



    /// @dev Called by the old FeesWallet contract.

    /// Part of the IMigratableFeesWallet interface.

    function acceptBucketMigration(uint256 bucketStartTime, uint256 amount) external;



    /// @dev an emergency withdrawal enables withdrawal of all funds to an escrow account. To be use in emergencies only.

    function emergencyWithdraw() external /* onlyMigrationManager */;



}

interface ILockable {



    event Locked();

    event Unlocked();



    function lock() external /* onlyLockOwner */;

    function unlock() external /* onlyLockOwner */;

    function isLocked() view external returns (bool);



}

interface IMigratableFeesWallet {

    /// @dev receives a bucket start time and an amount

    function acceptBucketMigration(uint256 bucketStartTime, uint256 amount) external;

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

contract FeesAndBootstrapRewards is IFeesAndBootstrapRewards, ManagedContract {

    using SafeMath for uint256;

    using SafeMath96 for uint96;



    uint256 constant PERCENT_MILLIE_BASE = 100000;

    uint256 constant TOKEN_BASE = 1e18;



    struct Settings {

        uint96 generalCommitteeAnnualBootstrap;

        uint96 certifiedCommitteeAnnualBootstrap;

        bool rewardAllocationActive;

    }

    Settings settings;



    IERC20 public bootstrapToken;

    IERC20 public erc20;



    struct FeesAndBootstrapState {

        uint96 certifiedFeesPerMember;

        uint96 generalFeesPerMember;

        uint96 certifiedBootstrapPerMember;

        uint96 generalBootstrapPerMember;

        uint32 lastAssigned;

    }

    FeesAndBootstrapState public feesAndBootstrapState;



    struct FeesAndBootstrap {

        uint96 feeBalance;

        uint96 lastFeesPerMember;

        uint96 bootstrapBalance;

        uint96 lastBootstrapPerMember;

    }

    mapping(address => FeesAndBootstrap) public feesAndBootstrap;



    constructor(

        IContractRegistry _contractRegistry,

        address _registryAdmin,

        IERC20 _erc20,

        IERC20 _bootstrapToken,

        uint generalCommitteeAnnualBootstrap,

        uint certifiedCommitteeAnnualBootstrap

    ) ManagedContract(_contractRegistry, _registryAdmin) public {

        require(address(_bootstrapToken) != address(0), "bootstrapToken must not be 0");

        require(address(_erc20) != address(0), "erc20 must not be 0");



        _setGeneralCommitteeAnnualBootstrap(generalCommitteeAnnualBootstrap);

        _setCertifiedCommitteeAnnualBootstrap(certifiedCommitteeAnnualBootstrap);



        erc20 = _erc20;

        bootstrapToken = _bootstrapToken;

    }



    modifier onlyCommitteeContract() {

        require(msg.sender == address(committeeContract), "caller is not the elections contract");



        _;

    }



    /*

    * External functions

    */



    function committeeMembershipWillChange(address guardian, bool inCommittee, bool isCertified, bool nextCertification, uint generalCommitteeSize, uint certifiedCommitteeSize) external override onlyWhenActive onlyCommitteeContract {

        _updateGuardianFeesAndBootstrap(guardian, inCommittee, isCertified, nextCertification, generalCommitteeSize, certifiedCommitteeSize);

    }



    function getFeesAndBootstrapBalance(address guardian) external override view returns (uint256 feeBalance, uint256 bootstrapBalance) {

        FeesAndBootstrap memory guardianFeesAndBootstrap = getGuardianFeesAndBootstrap(guardian);

        return (guardianFeesAndBootstrap.feeBalance, guardianFeesAndBootstrap.bootstrapBalance);

    }



    function withdrawBootstrapFunds(address guardian) external override onlyWhenActive {

        updateGuardianFeesAndBootstrap(guardian);

        uint256 amount = feesAndBootstrap[guardian].bootstrapBalance;

        feesAndBootstrap[guardian].bootstrapBalance = 0;

        emit BootstrapRewardsWithdrawn(guardian, amount);



        require(bootstrapToken.transfer(guardian, amount), "Rewards::withdrawBootstrapFunds - insufficient funds");

    }



    function withdrawFees(address guardian) external override onlyWhenActive {

        updateGuardianFeesAndBootstrap(guardian);



        uint256 amount = feesAndBootstrap[guardian].feeBalance;

        feesAndBootstrap[guardian].feeBalance = 0;

        emit FeesWithdrawn(guardian, amount);

        require(erc20.transfer(guardian, amount), "Rewards::withdrawFees - insufficient funds");

    }



    function getFeesAndBootstrapState() external override view returns (

        uint256 certifiedFeesPerMember,

        uint256 generalFeesPerMember,

        uint256 certifiedBootstrapPerMember,

        uint256 generalBootstrapPerMember,

        uint256 lastAssigned

    ) {

        (uint generalCommitteeSize, uint certifiedCommitteeSize, ) = committeeContract.getCommitteeStats();

        (FeesAndBootstrapState memory _feesAndBootstrapState,) = _getFeesAndBootstrapState(generalCommitteeSize, certifiedCommitteeSize, generalFeesWallet.getOutstandingFees(), certifiedFeesWallet.getOutstandingFees(), settings);

        certifiedFeesPerMember = _feesAndBootstrapState.certifiedFeesPerMember;

        generalFeesPerMember = _feesAndBootstrapState.generalFeesPerMember;

        certifiedBootstrapPerMember = _feesAndBootstrapState.certifiedBootstrapPerMember;

        generalBootstrapPerMember = _feesAndBootstrapState.generalBootstrapPerMember;

        lastAssigned = _feesAndBootstrapState.lastAssigned;

    }



    function getFeesAndBootstrapData(address guardian) external override view returns (

        uint256 feeBalance,

        uint256 lastFeesPerMember,

        uint256 bootstrapBalance,

        uint256 lastBootstrapPerMember

    ) {

        FeesAndBootstrap memory guardianFeesAndBootstrap = getGuardianFeesAndBootstrap(guardian);

        return (

            guardianFeesAndBootstrap.feeBalance,

            guardianFeesAndBootstrap.lastFeesPerMember,

            guardianFeesAndBootstrap.bootstrapBalance,

            guardianFeesAndBootstrap.lastBootstrapPerMember

        );

    }



    /*

     * Governance functions

     */



    function migrateRewardsBalance(address guardian) external override {

        require(!settings.rewardAllocationActive, "Reward distribution must be deactivated for migration");



        IFeesAndBootstrapRewards currentRewardsContract = IFeesAndBootstrapRewards(getFeesAndBootstrapRewardsContract());

        require(address(currentRewardsContract) != address(this), "New rewards contract is not set");



        updateGuardianFeesAndBootstrap(guardian);



        FeesAndBootstrap memory guardianFeesAndBootstrap = feesAndBootstrap[guardian];

        uint256 fees = guardianFeesAndBootstrap.feeBalance;

        uint256 bootstrap = guardianFeesAndBootstrap.bootstrapBalance;



        guardianFeesAndBootstrap.feeBalance = 0;

        guardianFeesAndBootstrap.bootstrapBalance = 0;

        feesAndBootstrap[guardian] = guardianFeesAndBootstrap;



        require(erc20.approve(address(currentRewardsContract), fees), "migrateRewardsBalance: approve failed");

        require(bootstrapToken.approve(address(currentRewardsContract), bootstrap), "migrateRewardsBalance: approve failed");

        currentRewardsContract.acceptRewardsBalanceMigration(guardian, fees, bootstrap);



        emit FeesAndBootstrapRewardsBalanceMigrated(guardian, fees, bootstrap, address(currentRewardsContract));

    }



    function acceptRewardsBalanceMigration(address guardian, uint256 fees, uint256 bootstrap) external override {

        FeesAndBootstrap memory guardianFeesAndBootstrap = feesAndBootstrap[guardian];

        guardianFeesAndBootstrap.feeBalance = guardianFeesAndBootstrap.feeBalance.add(fees);

        guardianFeesAndBootstrap.bootstrapBalance = guardianFeesAndBootstrap.bootstrapBalance.add(bootstrap);

        feesAndBootstrap[guardian] = guardianFeesAndBootstrap;



        if (fees > 0) {

            require(erc20.transferFrom(msg.sender, address(this), fees), "acceptRewardBalanceMigration: transfer failed");

        }

        if (bootstrap > 0) {

            require(bootstrapToken.transferFrom(msg.sender, address(this), bootstrap), "acceptRewardBalanceMigration: transfer failed");

        }



        emit FeesAndBootstrapRewardsBalanceMigrationAccepted(msg.sender, guardian, fees, bootstrap);

    }



    function activateRewardDistribution(uint startTime) external override onlyMigrationManager {

        feesAndBootstrapState.lastAssigned = uint32(startTime);

        settings.rewardAllocationActive = true;



        emit RewardDistributionActivated(startTime);

    }



    function deactivateRewardDistribution() external override onlyMigrationManager {

        require(settings.rewardAllocationActive, "reward distribution is already deactivated");



        updateFeesAndBootstrapState();



        settings.rewardAllocationActive = false;



        emit RewardDistributionDeactivated();

    }



    function getSettings() external override view returns (

        uint generalCommitteeAnnualBootstrap,

        uint certifiedCommitteeAnnualBootstrap,

        bool rewardAllocationActive

    ) {

        Settings memory _settings = settings;

        generalCommitteeAnnualBootstrap = _settings.generalCommitteeAnnualBootstrap;

        certifiedCommitteeAnnualBootstrap = _settings.certifiedCommitteeAnnualBootstrap;

        rewardAllocationActive = _settings.rewardAllocationActive;

    }



    function setGeneralCommitteeAnnualBootstrap(uint256 annualAmount) external override onlyFunctionalManager {

        updateFeesAndBootstrapState();

        _setGeneralCommitteeAnnualBootstrap(annualAmount);

    }



    function getGeneralCommitteeAnnualBootstrap() external override view returns (uint256) {

        return settings.generalCommitteeAnnualBootstrap;

    }



    function setCertifiedCommitteeAnnualBootstrap(uint256 annualAmount) external override onlyFunctionalManager {

        updateFeesAndBootstrapState();

        _setCertifiedCommitteeAnnualBootstrap(annualAmount);

    }



    function getCertifiedCommitteeAnnualBootstrap() external override view returns (uint256) {

        return settings.certifiedCommitteeAnnualBootstrap;

    }



    function emergencyWithdraw() external override onlyMigrationManager {

        emit EmergencyWithdrawal(msg.sender);

        require(erc20.transfer(msg.sender, erc20.balanceOf(address(this))), "Rewards::emergencyWithdraw - transfer failed (fee token)");

        require(bootstrapToken.transfer(msg.sender, bootstrapToken.balanceOf(address(this))), "Rewards::emergencyWithdraw - transfer failed (bootstrap token)");

    }



    function isRewardAllocationActive() external override view returns (bool) {

        return settings.rewardAllocationActive;

    }



    /*

    * Private functions

    */



    // Global state



    function _getFeesAndBootstrapState(uint generalCommitteeSize, uint certifiedCommitteeSize, uint256 collectedGeneralFees, uint256 collectedCertifiedFees, Settings memory _settings) private view returns (FeesAndBootstrapState memory _feesAndBootstrapState, uint256 allocatedBootstrap) {

        _feesAndBootstrapState = feesAndBootstrapState;



        if (_settings.rewardAllocationActive) {

            uint256 generalFeesDelta = generalCommitteeSize == 0 ? 0 : collectedGeneralFees.div(generalCommitteeSize);

            uint256 certifiedFeesDelta = generalFeesDelta.add(certifiedCommitteeSize == 0 ? 0 : collectedCertifiedFees.div(certifiedCommitteeSize));



            _feesAndBootstrapState.generalFeesPerMember = _feesAndBootstrapState.generalFeesPerMember.add(generalFeesDelta);

            _feesAndBootstrapState.certifiedFeesPerMember = _feesAndBootstrapState.certifiedFeesPerMember.add(certifiedFeesDelta);



            uint duration = block.timestamp.sub(_feesAndBootstrapState.lastAssigned);

            uint256 generalBootstrapDelta = uint256(_settings.generalCommitteeAnnualBootstrap).mul(duration).div(365 days);

            uint256 certifiedBootstrapDelta = generalBootstrapDelta.add(uint256(_settings.certifiedCommitteeAnnualBootstrap).mul(duration).div(365 days));



            _feesAndBootstrapState.generalBootstrapPerMember = _feesAndBootstrapState.generalBootstrapPerMember.add(generalBootstrapDelta);

            _feesAndBootstrapState.certifiedBootstrapPerMember = _feesAndBootstrapState.certifiedBootstrapPerMember.add(certifiedBootstrapDelta);

            _feesAndBootstrapState.lastAssigned = uint32(block.timestamp);



            allocatedBootstrap = generalBootstrapDelta.mul(generalCommitteeSize).add(certifiedBootstrapDelta.mul(certifiedCommitteeSize));

        }

    }



    function _updateFeesAndBootstrapState(uint generalCommitteeSize, uint certifiedCommitteeSize) private returns (FeesAndBootstrapState memory _feesAndBootstrapState) {

        Settings memory _settings = settings;

        if (!_settings.rewardAllocationActive) {

            return feesAndBootstrapState;

        }



        uint256 collectedGeneralFees = generalFeesWallet.collectFees();

        uint256 collectedCertifiedFees = certifiedFeesWallet.collectFees();

        uint256 allocatedBootstrap;



        (_feesAndBootstrapState, allocatedBootstrap) = _getFeesAndBootstrapState(generalCommitteeSize, certifiedCommitteeSize, collectedGeneralFees, collectedCertifiedFees, _settings);

        bootstrapRewardsWallet.withdraw(allocatedBootstrap);



        feesAndBootstrapState = _feesAndBootstrapState;

    }



    function updateFeesAndBootstrapState() private returns (FeesAndBootstrapState memory _feesAndBootstrapState) {

        (uint generalCommitteeSize, uint certifiedCommitteeSize, ) = committeeContract.getCommitteeStats();

        return _updateFeesAndBootstrapState(generalCommitteeSize, certifiedCommitteeSize);

    }



    // Guardian state



    function _getGuardianFeesAndBootstrap(address guardian, bool inCommittee, bool isCertified, bool nextCertification, FeesAndBootstrapState memory _feesAndBootstrapState) private view returns (FeesAndBootstrap memory guardianFeesAndBootstrap, uint256 addedBootstrapAmount, uint256 addedFeesAmount) {

        guardianFeesAndBootstrap = feesAndBootstrap[guardian];



        if (inCommittee) {

            addedBootstrapAmount = (isCertified ? _feesAndBootstrapState.certifiedBootstrapPerMember : _feesAndBootstrapState.generalBootstrapPerMember).sub(guardianFeesAndBootstrap.lastBootstrapPerMember);

            guardianFeesAndBootstrap.bootstrapBalance = guardianFeesAndBootstrap.bootstrapBalance.add(addedBootstrapAmount);



            addedFeesAmount = (isCertified ? _feesAndBootstrapState.certifiedFeesPerMember : _feesAndBootstrapState.generalFeesPerMember).sub(guardianFeesAndBootstrap.lastFeesPerMember);

            guardianFeesAndBootstrap.feeBalance = guardianFeesAndBootstrap.feeBalance.add(addedFeesAmount);

        }



        guardianFeesAndBootstrap.lastBootstrapPerMember = nextCertification ?  _feesAndBootstrapState.certifiedBootstrapPerMember : _feesAndBootstrapState.generalBootstrapPerMember;

        guardianFeesAndBootstrap.lastFeesPerMember = nextCertification ?  _feesAndBootstrapState.certifiedFeesPerMember : _feesAndBootstrapState.generalFeesPerMember;

    }



    function _updateGuardianFeesAndBootstrap(address guardian, bool inCommittee, bool isCertified, bool nextCertification, uint generalCommitteeSize, uint certifiedCommitteeSize) private {

        uint256 addedBootstrapAmount;

        uint256 addedFeesAmount;



        FeesAndBootstrapState memory _feesAndBootstrapState = _updateFeesAndBootstrapState(generalCommitteeSize, certifiedCommitteeSize);

        (feesAndBootstrap[guardian], addedBootstrapAmount, addedFeesAmount) = _getGuardianFeesAndBootstrap(guardian, inCommittee, isCertified, nextCertification, _feesAndBootstrapState);



        emit BootstrapRewardsAssigned(guardian, addedBootstrapAmount);

        emit FeesAssigned(guardian, addedFeesAmount);

    }



    function getGuardianFeesAndBootstrap(address guardian) private view returns (FeesAndBootstrap memory guardianFeesAndBootstrap) {

        ICommittee _committeeContract = committeeContract;

        (uint generalCommitteeSize, uint certifiedCommitteeSize, ) = _committeeContract.getCommitteeStats();

        (FeesAndBootstrapState memory _feesAndBootstrapState,) = _getFeesAndBootstrapState(generalCommitteeSize, certifiedCommitteeSize, generalFeesWallet.getOutstandingFees(), certifiedFeesWallet.getOutstandingFees(), settings);

        (bool inCommittee, , bool isCertified,) = _committeeContract.getMemberInfo(guardian);

        (guardianFeesAndBootstrap, ,) = _getGuardianFeesAndBootstrap(guardian, inCommittee, isCertified, isCertified, _feesAndBootstrapState);

    }



    function updateGuardianFeesAndBootstrap(address guardian) private {

        ICommittee _committeeContract = committeeContract;

        (uint generalCommitteeSize, uint certifiedCommitteeSize, ) = _committeeContract.getCommitteeStats();

        (bool inCommittee, , bool isCertified,) = _committeeContract.getMemberInfo(guardian);

        _updateGuardianFeesAndBootstrap(guardian, inCommittee, isCertified, isCertified, generalCommitteeSize, certifiedCommitteeSize);

    }



    // Governance and misc.



    function _setGeneralCommitteeAnnualBootstrap(uint256 annualAmount) private {

        require(uint256(uint96(annualAmount)) == annualAmount, "annualAmount must fit in uint96");



        settings.generalCommitteeAnnualBootstrap = uint96(annualAmount);

        emit GeneralCommitteeAnnualBootstrapChanged(annualAmount);

    }



    function _setCertifiedCommitteeAnnualBootstrap(uint256 annualAmount) private {

        require(uint256(uint96(annualAmount)) == annualAmount, "annualAmount must fit in uint96");



        settings.certifiedCommitteeAnnualBootstrap = uint96(annualAmount);

        emit CertifiedCommitteeAnnualBootstrapChanged(annualAmount);

    }



    /*

     * Contracts topology / registry interface

     */



    ICommittee committeeContract;

    IFeesWallet generalFeesWallet;

    IFeesWallet certifiedFeesWallet;

    IProtocolWallet bootstrapRewardsWallet;

    function refreshContracts() external override {

        committeeContract = ICommittee(getCommitteeContract());

        generalFeesWallet = IFeesWallet(getGeneralFeesWallet());

        certifiedFeesWallet = IFeesWallet(getCertifiedFeesWallet());

        bootstrapRewardsWallet = IProtocolWallet(getBootstrapRewardsWallet());

    }

}
