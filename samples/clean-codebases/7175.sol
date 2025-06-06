// File: @openzeppelin\contracts-ethereum-package\contracts\token\ERC20\IERC20.sol

pragma solidity ^0.5.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP. Does not include
 * the optional functions; to access them see {ERC20Detailed}.
 */
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

// File: @openzeppelin\contracts-ethereum-package\contracts\math\SafeMath.sol

pragma solidity ^0.5.0;

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
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
     * - Subtraction cannot overflow.
     *
     * _Available since v2.4.0._
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
     * - The divisor cannot be zero.
     *
     * _Available since v2.4.0._
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
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
     * - The divisor cannot be zero.
     *
     * _Available since v2.4.0._
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

// File: @openzeppelin\contracts-ethereum-package\contracts\utils\Address.sol

pragma solidity ^0.5.5;

/**
 * @dev Collection of functions related to the address type
 */
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
        // According to EIP-1052, 0x0 is the value returned for not-yet created accounts
        // and 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 is returned
        // for accounts without code, i.e. `keccak256('')`
        bytes32 codehash;
        bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
        // solhint-disable-next-line no-inline-assembly
        assembly { codehash := extcodehash(account) }
        return (codehash != accountHash && codehash != 0x0);
    }

    /**
     * @dev Converts an `address` into `address payable`. Note that this is
     * simply a type cast: the actual underlying value is not changed.
     *
     * _Available since v2.4.0._
     */
    function toPayable(address account) internal pure returns (address payable) {
        return address(uint160(account));
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
     *
     * _Available since v2.4.0._
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-call-value
        (bool success, ) = recipient.call.value(amount)("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }
}

// File: @openzeppelin\contracts-ethereum-package\contracts\token\ERC20\SafeERC20.sol

pragma solidity ^0.5.0;




/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for ERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value, "SafeERC20: decreased allowance below zero");
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// File: @openzeppelin\upgrades\contracts\Initializable.sol

pragma solidity >=0.4.24 <0.7.0;


/**
 * @title Initializable
 *
 * @dev Helper contract to support initializer functions. To use it, replace
 * the constructor with a function that has the `initializer` modifier.
 * WARNING: Unlike constructors, initializer functions must be manually
 * invoked. This applies both to deploying an Initializable contract, as well
 * as extending an Initializable contract via inheritance.
 * WARNING: When used with inheritance, manual care must be taken to not invoke
 * a parent initializer twice, or ensure that all initializers are idempotent,
 * because this is not dealt with automatically as with constructors.
 */
contract Initializable {

  /**
   * @dev Indicates that the contract has been initialized.
   */
  bool private initialized;

  /**
   * @dev Indicates that the contract is in the process of being initialized.
   */
  bool private initializing;

  /**
   * @dev Modifier to use in the initializer function of a contract.
   */
  modifier initializer() {
    require(initializing || isConstructor() || !initialized, "Contract instance has already been initialized");

    bool isTopLevelCall = !initializing;
    if (isTopLevelCall) {
      initializing = true;
      initialized = true;
    }

    _;

    if (isTopLevelCall) {
      initializing = false;
    }
  }

  /// @dev Returns true if and only if the function is running in the constructor
  function isConstructor() private view returns (bool) {
    // extcodesize checks the size of the code stored in an address, and
    // address returns the current address. Since the code is still not
    // deployed when running a constructor, any checks on its code size will
    // yield zero, making it an effective way to detect if a contract is
    // under construction or not.
    address self = address(this);
    uint256 cs;
    assembly { cs := extcodesize(self) }
    return cs == 0;
  }

  // Reserved storage space to allow for layout changes in the future.
  uint256[50] private ______gap;
}

// File: @openzeppelin\contracts-ethereum-package\contracts\GSN\Context.sol

pragma solidity ^0.5.0;


/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
contract Context is Initializable {
    // Empty internal constructor, to prevent people from mistakenly deploying
    // an instance of this contract, which should be used via inheritance.
    constructor () internal { }
    // solhint-disable-previous-line no-empty-blocks

    function _msgSender() internal view returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

// File: @openzeppelin\contracts-ethereum-package\contracts\ownership\Ownable.sol

pragma solidity ^0.5.0;



/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be aplied to your functions to restrict their use to
 * the owner.
 */
contract Ownable is Initializable, Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    function initialize(address sender) public initializer {
        _owner = sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(isOwner(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Returns true if the caller is the current owner.
     */
    function isOwner() public view returns (bool) {
        return _msgSender() == _owner;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * > Note: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    uint256[50] private ______gap;
}

// File: contracts\common\Base.sol

pragma solidity ^0.5.12;




/**
 * Base contract for all modules
 */
contract Base is Initializable, Context, Ownable {
    address constant  ZERO_ADDRESS = address(0);

    function initialize() public initializer {
        Ownable.initialize(_msgSender());
    }

}

// File: contracts\core\ModuleNames.sol

pragma solidity ^0.5.12;

/**
 * @dev List of module names
 */
contract ModuleNames {
    // Pool Modules
    string internal constant MODULE_ACCESS            = "access";
    string internal constant MODULE_SAVINGS           = "savings";
    string internal constant MODULE_INVESTING         = "investing";
    string internal constant MODULE_STAKING_AKRO      = "staking";
    string internal constant MODULE_STAKING_ADEL      = "stakingAdel";
    string internal constant MODULE_DCA               = "dca";
    string internal constant MODULE_REWARD            = "reward";
    string internal constant MODULE_REWARD_DISTR      = "rewardDistributions";
    string internal constant MODULE_VAULT             = "vault";

    // Pool tokens
    string internal constant TOKEN_AKRO               = "akro";    
    string internal constant TOKEN_ADEL               = "adel";    

    // External Modules (used to store addresses of external contracts)
    string internal constant CONTRACT_RAY             = "ray";
}

// File: contracts\common\Module.sol

pragma solidity ^0.5.12;



/**
 * Base contract for all modules
 */
contract Module is Base, ModuleNames {
    event PoolAddressChanged(address newPool);
    address public pool;

    function initialize(address _pool) public initializer {
        Base.initialize();
        setPool(_pool);
    }

    function setPool(address _pool) public onlyOwner {
        require(_pool != ZERO_ADDRESS, "Module: pool address can't be zero");
        pool = _pool;
        emit PoolAddressChanged(_pool);        
    }

    function getModuleAddress(string memory module) public view returns(address){
        require(pool != ZERO_ADDRESS, "Module: no pool");
        (bool success, bytes memory result) = pool.staticcall(abi.encodeWithSignature("get(string)", module));
        
        //Forward error from Pool contract
        if (!success) assembly {
            revert(add(result, 32), result)
        }

        address moduleAddress = abi.decode(result, (address));
        // string memory error = string(abi.encodePacked("Module: requested module not found - ", module));
        // require(moduleAddress != ZERO_ADDRESS, error);
        require(moduleAddress != ZERO_ADDRESS, "Module: requested module not found");
        return moduleAddress;
    }

}

// File: @openzeppelin\contracts-ethereum-package\contracts\access\Roles.sol

pragma solidity ^0.5.0;

/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev Give an account access to this role.
     */
    function add(Role storage role, address account) internal {
        require(!has(role, account), "Roles: account already has role");
        role.bearer[account] = true;
    }

    /**
     * @dev Remove an account's access to this role.
     */
    function remove(Role storage role, address account) internal {
        require(has(role, account), "Roles: account does not have role");
        role.bearer[account] = false;
    }

    /**
     * @dev Check if an account has this role.
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0), "Roles: account is the zero address");
        return role.bearer[account];
    }
}

// File: contracts\modules\defi\DefiOperatorRole.sol

pragma solidity ^0.5.12;




contract DefiOperatorRole is Initializable, Context {
    using Roles for Roles.Role;

    event DefiOperatorAdded(address indexed account);
    event DefiOperatorRemoved(address indexed account);

    Roles.Role private _operators;

    function initialize(address sender) public initializer {
        if (!isDefiOperator(sender)) {
            _addDefiOperator(sender);
        }
    }

    modifier onlyDefiOperator() {
        require(isDefiOperator(_msgSender()), "DefiOperatorRole: caller does not have the DefiOperator role");
        _;
    }

    function addDefiOperator(address account) public onlyDefiOperator {
        _addDefiOperator(account);
    }

    function renounceDefiOperator() public {
        _removeDefiOperator(_msgSender());
    }

    function isDefiOperator(address account) public view returns (bool) {
        return _operators.has(account);
    }

    function _addDefiOperator(address account) internal {
        _operators.add(account);
        emit DefiOperatorAdded(account);
    }

    function _removeDefiOperator(address account) internal {
        _operators.remove(account);
        emit DefiOperatorRemoved(account);
    }

}

// File: contracts\interfaces\defi\IDefiStrategy.sol

pragma solidity ^0.5.12;

contract IDefiStrategy { 
    /**
     * @notice Transfer tokens from sender to DeFi protocol
     * @param token Address of token
     * @param amount Value of token to deposit
     * @return new balances of each token
     */
    function handleDeposit(address token, uint256 amount) external;

    function handleDeposit(address[] calldata tokens, uint256[] calldata amounts) external;

    function withdraw(address beneficiary, address token, uint256 amount) external;

    function withdraw(address beneficiary, uint256[] calldata amounts) external;

    function setVault(address _vault) external;

    function normalizedBalance() external returns(uint256);
    function balanceOf(address token) external returns(uint256);
    function balanceOfAll() external returns(uint256[] memory balances);

    function getStrategyId() external view returns(string memory);
}

// File: contracts\interfaces\defi\IStrategyCurveFiSwapCrv.sol

pragma solidity ^0.5.12;

interface IStrategyCurveFiSwapCrv {
    event CrvClaimed(string indexed id, address strategy, uint256 amount);

    function curveFiTokenBalance() external view returns(uint256);
    function performStrategyStep1() external;
    function performStrategyStep2(bytes calldata _data, address _token) external;
}

// File: contracts\interfaces\defi\IVaultProtocol.sol

pragma solidity ^0.5.12;

//solhint-disable func-order
contract IVaultProtocol {
    event DepositToVault(address indexed _user, address indexed _token, uint256 _amount);
    event WithdrawFromVault(address indexed _user, address indexed _token, uint256 _amount);
    event WithdrawRequestCreated(address indexed _user, address indexed _token, uint256 _amount);
    event DepositByOperator(uint256 _amount);
    event WithdrawByOperator(uint256 _amount);
    event WithdrawRequestsResolved(uint256 _totalDeposit, uint256 _totalWithdraw);
    event StrategyRegistered(address indexed _vault, address indexed _strategy, string _id);

    event Claimed(address indexed _vault, address indexed _user, address _token, uint256 _amount);
    event DepositsCleared(address indexed _vault);
    event RequestsCleared(address indexed _vault);


    function registerStrategy(address _strategy) external;

    function depositToVault(address _user, address _token, uint256 _amount) external;
    function depositToVault(address _user, address[] calldata  _tokens, uint256[] calldata _amounts) external;

    function withdrawFromVault(address _user, address _token, uint256 _amount) external;
    function withdrawFromVault(address _user, address[] calldata  _tokens, uint256[] calldata _amounts) external;

    function operatorAction(address _strategy) external returns(uint256, uint256);
    function operatorActionOneCoin(address _strategy, address _token) external returns(uint256, uint256);
    function clearOnHoldDeposits() external;
    function clearWithdrawRequests() external;
    function setRemainder(uint256 _amount, uint256 _index) external;

    function quickWithdraw(address _user, address[] calldata _tokens, uint256[] calldata _amounts) external;
    function quickWithdrawStrategy() external view returns(address);

    function claimRequested(address _user) external;

    function normalizedBalance() external returns(uint256);
    function normalizedBalance(address _strategy) external returns(uint256);
    function normalizedVaultBalance() external view returns(uint256);

    function supportedTokens() external view returns(address[] memory);
    function supportedTokensCount() external view returns(uint256);

    function isStrategyRegistered(address _strategy) external view returns(bool);
    function registeredStrategies() external view returns(address[] memory);

    function isTokenRegistered(address _token) external view returns (bool);
    function tokenRegisteredInd(address _token) external view returns(uint256);

    function totalClaimableAmount(address _token) external view returns (uint256);
    function claimableAmount(address _user, address _token) external view returns (uint256);

    function amountOnHold(address _user, address _token) external view returns (uint256);

    function amountRequested(address _user, address _token) external view returns (uint256);
}

// File: contracts\interfaces\defi\ICurveFiDeposit.sol

pragma solidity ^0.5.12;

contract ICurveFiDeposit { 
    function remove_liquidity_one_coin(uint256 _token_amount, int128 i, uint256 min_uamount) external;
    function remove_liquidity_one_coin(uint256 _token_amount, int128 i, uint256 min_uamount, bool donate_dust) external;
    function withdraw_donated_dust() external;

    function coins(int128 i) external view returns (address);
    function underlying_coins (int128 i) external view returns (address);
    function curve() external view returns (address);
    function token() external view returns (address);
    function calc_withdraw_one_coin (uint256 _token_amount, int128 i) external view returns (uint256);
}

// File: contracts\interfaces\defi\ICurveFiDeposit_Y.sol

pragma solidity ^0.5.12;

contract ICurveFiDeposit_Y { 
    function add_liquidity (uint256[4] calldata uamounts, uint256 min_mint_amount) external;
    function remove_liquidity (uint256 _amount, uint256[4] calldata min_uamounts) external;
    function remove_liquidity_imbalance (uint256[4] calldata uamounts, uint256 max_burn_amount) external;
}

// File: contracts\interfaces\defi\ICurveFiLiquidityGauge.sol

pragma solidity ^0.5.16;

interface ICurveFiLiquidityGauge {
    //Addresses of tokens
    function lp_token() external returns(address);
    function crv_token() external returns(address);
 
    //Work with LP tokens
    function balanceOf(address addr) external view returns (uint256);
    function deposit(uint256 _value) external;
    function withdraw(uint256 _value) external;

    //Work with CRV
    function claimable_tokens(address addr) external returns (uint256);
    function minter() external view returns(address); //use minter().mint(gauge_addr) to claim CRV

    function integrate_fraction(address _for) external returns(uint256);
    function user_checkpoint(address _for) external returns(bool);
}

// File: contracts\interfaces\defi\ICurveFiMinter.sol

pragma solidity ^0.5.16;

interface ICurveFiMinter {
    function mint(address gauge_addr) external;
    function mint_for(address gauge_addr, address _for) external;
    function minted(address _for, address gauge_addr) external returns(uint256);
}

// File: contracts\interfaces\defi\ICurveFiSwap.sol

pragma solidity ^0.5.12;

interface ICurveFiSwap { 
    function balances(int128 i) external view returns(uint256);
    function A() external view returns(uint256);
    function fee() external view returns(uint256);
    function coins(int128 i) external view returns (address);
}

// File: contracts\interfaces\defi\IDexag.sol

pragma solidity ^0.5.12;

/**
 * Interfce for Dexag Proxy
 * https://github.com/ConcourseOpen/DEXAG-Proxy/blob/master/contracts/DexTradingWithCollection.sol
 */
interface IDexag {
    function approvalHandler() external returns(address);

    function trade(
        address from,
        address to,
        uint256 fromAmount,
        address[] calldata exchanges,
        address[] calldata approvals,
        bytes calldata data,
        uint256[] calldata offsets,
        uint256[] calldata etherValues,
        uint256 limitAmount,
        uint256 tradeType
    ) external payable;

}

// File: contracts\interfaces\defi\IYErc20.sol

pragma solidity ^0.5.12;

//solhint-disable func-order
contract IYErc20 { 

    //ERC20 functions
    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);

    //yToken functions
    function deposit(uint256 amount) external;
    function withdraw(uint256 shares) external;
    function getPricePerFullShare() external view returns (uint256);

    function token() external returns(address);

}

// File: @openzeppelin\contracts-ethereum-package\contracts\token\ERC20\ERC20Detailed.sol

pragma solidity ^0.5.0;



/**
 * @dev Optional functions from the ERC20 standard.
 */
contract ERC20Detailed is Initializable, IERC20 {
    string private _name;
    string private _symbol;
    uint8 private _decimals;

    /**
     * @dev Sets the values for `name`, `symbol`, and `decimals`. All three of
     * these values are immutable: they can only be set once during
     * construction.
     */
    function initialize(string memory name, string memory symbol, uint8 decimals) public initializer {
        _name = name;
        _symbol = symbol;
        _decimals = decimals;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5,05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei.
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view returns (uint8) {
        return _decimals;
    }

    uint256[50] private ______gap;
}

// File: contracts\utils\CalcUtils.sol

pragma solidity ^0.5.12;



library CalcUtils {
     using SafeMath for uint256;

    function normalizeAmount(address coin, uint256 amount) internal view returns(uint256) {
        uint8 decimals = ERC20Detailed(coin).decimals();
        if (decimals == 18) {
            return amount;
        } else if (decimals > 18) {
            return amount.div(uint256(10)**(decimals-18));
        } else if (decimals < 18) {
            return amount.mul(uint256(10)**(18 - decimals));
        }
    }

    function denormalizeAmount(address coin, uint256 amount) internal view returns(uint256) {
        uint256 decimals = ERC20Detailed(coin).decimals();
        if (decimals == 18) {
            return amount;
        } else if (decimals > 18) {
            return amount.mul(uint256(10)**(decimals-18));
        } else if (decimals < 18) {
            return amount.div(uint256(10)**(18 - decimals));
        }
    }

}

// File: contracts\modules\defi\CurveFiStablecoinStrategy.sol

pragma solidity ^0.5.12;


















contract CurveFiStablecoinStrategy is Module, IDefiStrategy, IStrategyCurveFiSwapCrv, DefiOperatorRole {
    using SafeMath for uint256;
    using SafeERC20 for IERC20;


    struct PriceData {
        uint256 price;
        uint256 lastUpdateBlock;
    }

    address public vault;

    ICurveFiDeposit public curveFiDeposit;
    IERC20 public curveFiToken;
    ICurveFiLiquidityGauge public curveFiLPGauge;
    ICurveFiSwap public curveFiSwap;
    ICurveFiMinter public curveFiMinter;
    uint256 public slippageMultiplier;
    address public crvToken;
    
    address public dexagProxy;
    address public dexagApproveHandler;

    string internal strategyId;

    mapping(address=>PriceData) internal yPricePerFullShare;

    //Register stablecoins contracts addresses
    function initialize(address _pool, string memory _strategyId) public initializer {
        Module.initialize(_pool);
        DefiOperatorRole.initialize(_msgSender());
        slippageMultiplier = 1.01*1e18;
        strategyId = _strategyId;
    }

    function setProtocol(address _depositContract, address _liquidityGauge, address _curveFiMinter, address _dexagProxy) public onlyDefiOperator {
        require(_depositContract != address(0), "Incorrect deposit contract address");

        curveFiDeposit = ICurveFiDeposit(_depositContract);
        curveFiLPGauge = ICurveFiLiquidityGauge(_liquidityGauge);
        curveFiMinter = ICurveFiMinter(_curveFiMinter);
        curveFiSwap = ICurveFiSwap(curveFiDeposit.curve());

        curveFiToken = IERC20(curveFiDeposit.token());

        address lpToken = curveFiLPGauge.lp_token();
        require(lpToken == address(curveFiToken), "CurveFiProtocol: LP tokens do not match");

        crvToken = curveFiLPGauge.crv_token();

        dexagProxy = _dexagProxy;
        dexagApproveHandler = IDexag(_dexagProxy).approvalHandler();
    }

    function setVault(address _vault) public onlyDefiOperator {
        vault = _vault;
    }

    function setDexagProxy(address _dexagProxy) public onlyDefiOperator {
        dexagProxy = _dexagProxy;
        dexagApproveHandler = IDexag(_dexagProxy).approvalHandler();
    }

    function handleDeposit(address token, uint256 amount) public onlyDefiOperator {
        uint256 nTokens = IVaultProtocol(vault).supportedTokensCount();
        uint256[] memory amounts = new uint256[](nTokens);
        uint256 ind = IVaultProtocol(vault).tokenRegisteredInd(token);

        for (uint256 i=0; i < nTokens; i++) {
            amounts[i] = uint256(0);
        }
        IERC20(token).safeTransferFrom(vault, address(this), amount);
        IERC20(token).safeApprove(address(curveFiDeposit), amount);
        amounts[ind] = amount;

        ICurveFiDeposit_Y(address(curveFiDeposit)).add_liquidity(convertArray(amounts), 0);

        //Stake Curve LP-token
        uint256 cftBalance = curveFiToken.balanceOf(address(this));
        curveFiToken.safeApprove(address(curveFiLPGauge), cftBalance);
        curveFiLPGauge.deposit(cftBalance);
    }

    function handleDeposit(address[] memory tokens, uint256[] memory amounts) public onlyDefiOperator {
        require(tokens.length == amounts.length, "Count of tokens does not match count of amounts");
        require(amounts.length == IVaultProtocol(vault).supportedTokensCount(), "Amounts count does not match registered tokens");

        for (uint256 i=0; i < tokens.length; i++) {
            IERC20(tokens[i]).safeTransferFrom(vault, address(this), amounts[i]);
            IERC20(tokens[i]).safeApprove(address(curveFiDeposit), amounts[i]);
        }

        //Check for sufficient amounts on the Vault balances is checked in the WithdrawOperator()
        //Correct amounts are also set in WithdrawOperator()

        //Deposit stablecoins into the protocol
        ICurveFiDeposit_Y(address(curveFiDeposit)).add_liquidity(convertArray(amounts), 0);

        //Stake Curve LP-token
        uint256 cftBalance = curveFiToken.balanceOf(address(this));
        curveFiToken.safeApprove(address(curveFiLPGauge), cftBalance);
        curveFiLPGauge.deposit(cftBalance);
    }

    function withdraw(address beneficiary, address token, uint256 amount) public onlyDefiOperator {
        uint256 tokenIdx = IVaultProtocol(vault).tokenRegisteredInd(token);

        //All withdrawn tokens are marked as claimable, so anyway we need to withdraw from the protocol

            // count shares for proportional withdraw
        uint256 nAmount = CalcUtils.normalizeAmount(token, amount);
        uint256 nBalance = normalizedBalance();

        uint256 poolShares = curveFiTokenBalance();
        uint256 withdrawShares = poolShares.mul(nAmount).mul(slippageMultiplier).div(nBalance).div(1e18); //Increase required amount to some percent, so that we definitely have enough to withdraw
        

        //Unstake Curve LP-token
        curveFiLPGauge.withdraw(withdrawShares);

        IERC20(curveFiToken).safeApprove(address(curveFiDeposit), withdrawShares);
        curveFiDeposit.remove_liquidity_one_coin(withdrawShares, int128(tokenIdx), amount, false); //DONATE_DUST - false

        IERC20(token).safeTransfer(beneficiary, amount);
    }

    function withdraw(address beneficiary, uint256[] memory amounts) public onlyDefiOperator {
        address[] memory registeredVaultTokens = IVaultProtocol(vault).supportedTokens();
        require(amounts.length == registeredVaultTokens.length, "Wrong amounts array length");

        //All withdrawn tokens are marked as claimable, so anyway we need to withdraw from the protocol
        uint256 nWithdraw;
        uint256 i;
        for (i = 0; i < registeredVaultTokens.length; i++) {
            address tkn = registeredVaultTokens[i];
            nWithdraw = nWithdraw.add(CalcUtils.normalizeAmount(tkn, amounts[i]));
        }

        uint256 nBalance = normalizedBalance();
        uint256 poolShares = curveFiTokenBalance();
        
        uint256 withdrawShares = poolShares.mul(nWithdraw).mul(slippageMultiplier).div(nBalance).div(1e18); //Increase required amount to some percent, so that we definitely have enough to withdraw

        //Unstake Curve LP-token
        curveFiLPGauge.withdraw(withdrawShares);

        IERC20(curveFiToken).safeApprove(address(curveFiDeposit), withdrawShares);
        ICurveFiDeposit_Y(address(curveFiDeposit)).remove_liquidity_imbalance(convertArray(amounts), withdrawShares);
        
        for (i = 0; i < registeredVaultTokens.length; i++){
            IERC20 lToken = IERC20(registeredVaultTokens[i]);
            uint256 lBalance = lToken.balanceOf(address(this));
            uint256 lAmount = (lBalance <= amounts[i])?lBalance:amounts[i]; // Rounding may prevent Curve.Fi to return exactly requested amount
            lToken.safeTransfer(beneficiary, lAmount);
        }
    }

    /**
     * @notice Operator should call this to receive CRV from curve
     */
    function performStrategyStep1() external onlyDefiOperator {
        claimRewardsFromProtocol();
        uint256 crvAmount = IERC20(crvToken).balanceOf(address(this));

        emit CrvClaimed(strategyId, address(this), crvAmount);
    }
    /**
     * @notice Operator should call this to exchange CRV to DAI
     */
    function performStrategyStep2(bytes calldata dexagSwapData, address swapStablecoin) external onlyDefiOperator {
        uint256 crvAmount = IERC20(crvToken).balanceOf(address(this));
        IERC20(crvToken).safeApprove(dexagApproveHandler, crvAmount);
        (bool success, bytes memory result) = dexagProxy.call(dexagSwapData);
        if(!success) assembly {
            revert(add(result,32), result)  //Reverts with same revert reason
        }
        //new dai tokens will be transferred to the Vault, they will be deposited by the operator on the next round
        //new LP tokens will be distributed automatically after the operator action
        uint256 amount = IERC20(swapStablecoin).balanceOf(address(this));
        IERC20(swapStablecoin).safeTransfer(vault, amount);
    }

    function curveFiTokenBalance() public view returns(uint256) {
        uint256 notStaked = curveFiToken.balanceOf(address(this));
        uint256 staked = curveFiLPGauge.balanceOf(address(this));
        return notStaked.add(staked);
    }

    function claimRewardsFromProtocol() internal {
        curveFiMinter.mint(address(curveFiLPGauge));
    }

    function balanceOf(address token) public returns(uint256) {
        uint256 tokenIdx = getTokenIndex(token);

        uint256 cfBalance = curveFiTokenBalance();
        uint256 cfTotalSupply = curveFiToken.totalSupply();
        uint256 yTokenCurveFiBalance = curveFiSwap.balances(int128(tokenIdx));
        
        uint256 yTokenShares = yTokenCurveFiBalance.mul(cfBalance).div(cfTotalSupply);
        uint256 tokenBalance = getPricePerFullShare(curveFiSwap.coins(int128(tokenIdx))).mul(yTokenShares).div(1e18); //getPricePerFullShare() returns balance of underlying token multiplied by 1e18

        return tokenBalance;
    }

    function balanceOfAll() public returns(uint256[] memory balances) {
        uint256 cfBalance = curveFiTokenBalance();
        uint256 cfTotalSupply = curveFiToken.totalSupply();
        uint256 nTokens = IVaultProtocol(vault).supportedTokensCount();

        require(cfTotalSupply > 0, "No Curve pool tokens minted");

        balances = new uint256[](nTokens);

        uint256 ycfBalance;
        for (uint256 i=0; i < nTokens; i++){
            ycfBalance =  curveFiSwap.balances(int128(i));
            uint256 yShares = ycfBalance.mul(cfBalance).div(cfTotalSupply);
            balances[i] = getPricePerFullShare(curveFiSwap.coins(int128(i))).mul(yShares).div(1e18);
        }
    }


    function normalizedBalance() public returns(uint256) {
        address[] memory registeredVaultTokens = IVaultProtocol(vault).supportedTokens();
        uint256[] memory balances = balanceOfAll();

        uint256 summ;
        for (uint256 i=0; i < registeredVaultTokens.length; i++){
            summ = summ.add(CalcUtils.normalizeAmount(registeredVaultTokens[i], balances[i]));
        }
        return summ;
    }

    function getStrategyId() public view returns(string memory) {
        return strategyId;
    }

    function convertArray(uint256[] memory amounts) internal pure returns(uint256[4] memory) {
        require(amounts.length == 4, "Wrong token count");
        uint256[4] memory amnts = [uint256(0), uint256(0), uint256(0), uint256(0)];
        for(uint256 i=0; i < 4; i++){
            amnts[i] = amounts[i];
        }
        return amnts;
    }

    function getTokenIndex(address token) public view returns(uint256) {
        address[] memory registeredVaultTokens = IVaultProtocol(vault).supportedTokens();
        for (uint256 i=0; i < registeredVaultTokens.length; i++){
            if (registeredVaultTokens[i] == token){
                return i;
            }
        }
        revert("CurveFiYProtocol: token not registered");
    }

    function getPricePerFullShare(address yToken) internal returns(uint256) {
        PriceData storage pd = yPricePerFullShare[yToken];
        if(pd.lastUpdateBlock < block.number) {
            pd.price = IYErc20(yToken).getPricePerFullShare();
            pd.lastUpdateBlock = block.number;
        }
        return pd.price;
    }
}