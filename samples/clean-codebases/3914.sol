/**
 *Submitted for verification at Etherscan.io on 2021-12-29
*/

// Sources flattened with hardhat v2.6.8 https://hardhat.org

// SPDX-License-Identifier: MIT

// File @openzeppelin/contracts/utils/[email protected]

pragma solidity >=0.6.0 <0.8.0;

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
abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}


// File @openzeppelin/contracts/access/[email protected]

pragma solidity ^0.7.0;

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}


// File @openzeppelin/contracts/math/[email protected]

pragma solidity ^0.7.0;

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
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        uint256 c = a + b;
        if (c < a) return (false, 0);
        return (true, c);
    }

    /**
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b > a) return (false, 0);
        return (true, a - b);
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) return (true, 0);
        uint256 c = a * b;
        if (c / a != b) return (false, 0);
        return (true, c);
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a / b);
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        if (b == 0) return (false, 0);
        return (true, a % b);
    }

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
        require(b <= a, "SafeMath: subtraction overflow");
        return a - b;
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
        if (a == 0) return 0;
        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");
        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
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
        require(b > 0, "SafeMath: division by zero");
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting when dividing by zero.
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
        require(b > 0, "SafeMath: modulo by zero");
        return a % b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {trySub}.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        return a - b;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryDiv}.
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
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting with custom message when dividing by zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryMod}.
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
        require(b > 0, errorMessage);
        return a % b;
    }
}


// File @openzeppelin/contracts/token/ERC20/[email protected]

pragma solidity ^0.7.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
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


// File @openzeppelin/contracts/utils/[email protected]

pragma solidity ^0.7.0;

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
        // This method relies on extcodesize, which returns 0 for contracts in
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
        (bool success, ) = recipient.call{ value: amount }("");
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
        return functionCallWithValue(target, data, 0, errorMessage);
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
        require(isContract(target), "Address: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
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


// File @openzeppelin/contracts/token/ERC20/[email protected]

pragma solidity ^0.7.0;



/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
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


// File @uniswap/lib/contracts/libraries/[email protected]

pragma solidity >=0.4.0;

// computes square roots using the babylonian method
// https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method
library Babylonian {
    // credit for this implementation goes to
    // https://github.com/abdk-consulting/abdk-libraries-solidity/blob/master/ABDKMath64x64.sol#L687
    function sqrt(uint256 x) internal pure returns (uint256) {
        if (x == 0) return 0;
        // this block is equivalent to r = uint256(1) << (BitMath.mostSignificantBit(x) / 2);
        // however that code costs significantly more gas
        uint256 xx = x;
        uint256 r = 1;
        if (xx >= 0x100000000000000000000000000000000) {
            xx >>= 128;
            r <<= 64;
        }
        if (xx >= 0x10000000000000000) {
            xx >>= 64;
            r <<= 32;
        }
        if (xx >= 0x100000000) {
            xx >>= 32;
            r <<= 16;
        }
        if (xx >= 0x10000) {
            xx >>= 16;
            r <<= 8;
        }
        if (xx >= 0x100) {
            xx >>= 8;
            r <<= 4;
        }
        if (xx >= 0x10) {
            xx >>= 4;
            r <<= 2;
        }
        if (xx >= 0x8) {
            r <<= 1;
        }
        r = (r + x / r) >> 1;
        r = (r + x / r) >> 1;
        r = (r + x / r) >> 1;
        r = (r + x / r) >> 1;
        r = (r + x / r) >> 1;
        r = (r + x / r) >> 1;
        r = (r + x / r) >> 1; // Seven iterations should be enough
        uint256 r1 = x / r;
        return (r < r1 ? r : r1);
    }
}


// File contracts/interfaces/ITreasury.sol

pragma solidity ^0.7.6;

interface ITreasury {
  enum ReserveType {
    // used by reserve manager, will not used to bond ALD.
    NULL,
    // used by main asset bond
    UNDERLYING,
    // used by vault reward bond
    VAULT_REWARD,
    // used by liquidity token bond
    LIQUIDITY_TOKEN
  }

  /// @dev return the usd value given token and amount.
  /// @param _token The address of token.
  /// @param _amount The amount of token.
  function valueOf(address _token, uint256 _amount) external view returns (uint256);

  /// @dev return the amount of bond ALD given token and usd value.
  /// @param _token The address of token.
  /// @param _value The usd of token.
  function bondOf(address _token, uint256 _value) external view returns (uint256);

  /// @dev deposit token to bond ALD.
  /// @param _type The type of deposited token.
  /// @param _token The address of token.
  /// @param _amount The amount of token.
  function deposit(
    ReserveType _type,
    address _token,
    uint256 _amount
  ) external returns (uint256);

  /// @dev withdraw token from POL.
  /// @param _token The address of token.
  /// @param _amount The amount of token.
  function withdraw(address _token, uint256 _amount) external;

  /// @dev manage token to earn passive yield.
  /// @param _token The address of token.
  /// @param _amount The amount of token.
  function manage(address _token, uint256 _amount) external;

  /// @dev mint ALD reward.
  /// @param _recipient The address of to receive ALD token.
  /// @param _amount The amount of token.
  function mintRewards(address _recipient, uint256 _amount) external;
}


// File contracts/interfaces/IUniswapV2Pair.sol

pragma solidity ^0.7.6;

interface IUniswapV2Pair {
  function totalSupply() external view returns (uint256);

  function token0() external view returns (address);

  function token1() external view returns (address);

  function getReserves()
    external
    view
    returns (
      uint112 reserve0,
      uint112 reserve1,
      uint32 blockTimestampLast
    );

  function price0CumulativeLast() external view returns (uint256);

  function price1CumulativeLast() external view returns (uint256);

  function mint(address to) external returns (uint256 liquidity);

  function swap(
    uint256 amount0Out,
    uint256 amount1Out,
    address to,
    bytes calldata data
  ) external;
}


// File contracts/POLExecutor.sol

pragma solidity ^0.7.6;






interface IUniswapV2Router {
  function swapExactTokensForTokens(
    uint256 amountIn,
    uint256 amountOutMin,
    address[] calldata path,
    address to,
    uint256 deadline
  ) external returns (uint256[] memory amounts);
}

contract POLExecutor is Ownable {
  using SafeERC20 for IERC20;
  using SafeMath for uint256;

  // The address of ALD Token.
  address private constant ald = 0xb26C4B3Ca601136Daf98593feAeff9E0CA702a8D;
  // The address of USDC Token.
  address private constant usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
  // The address of WETH Token.
  address private constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
  // The address of Aladdin DAO treasury.
  address private constant treasury = 0x5aa403275cdf5a487D195E8306FD0628D4F5747B;
  // The address of ALD/WETH pair.
  address private constant aldweth = 0xED6c2F053AF48Cba6cBC0958124671376f01A903;
  // The address of ALD/USDC pair.
  address private constant aldusdc = 0xaAa2bB0212Ec7190dC7142cD730173b0A788eC31;

  /// Mapping from whilelist address to status, true: whitelist, false: not whitelist.
  mapping(address => bool) public whitelist;

  modifier onlyWhitelist() {
    require(whitelist[msg.sender], "POLExecutor: only whitelist");
    _;
  }

  function updateWhitelist(address[] memory list, bool status) external onlyOwner {
    for (uint256 i = 0; i < list.length; i++) {
      whitelist[list[i]] = status;
    }
  }

  /// @dev Withdraw token from treasury and buy ald token.
  /// @param token The address of token to withdraw.
  /// @param amount The amount of token to withdraw.
  /// @param router The address of router to use, usually uniswap or sushiswap.
  /// @param toUSDC The path from token to USDC.
  /// @param toWETH The path from token to WETH.
  /// @param minALDAmount The minimum amount of ALD should buy.
  function withdrawAndSwapToALD(
    address token,
    uint256 amount,
    address router,
    address[] calldata toUSDC,
    address[] calldata toWETH,
    uint256 minALDAmount
  ) external onlyWhitelist {
    require(token != ald, "POLExecutor: token should not be ald");

    ITreasury(treasury).withdraw(token, amount);
    uint256 aldAmount;

    // swap to usdc and then to ald
    uint256 usdcAmount;
    if (token == usdc) {
      usdcAmount = amount / 2;
    } else {
      require(toUSDC[toUSDC.length - 1] == usdc, "POLExecutor: invalid toUSDC path");
      usdcAmount = _swapTo(token, amount / 2, router, toUSDC);
    }
    amount = amount - amount / 2;
    if (usdcAmount > 0) {
      aldAmount = aldAmount.add(_swapToALD(aldusdc, usdc, usdcAmount));
    }
    // swap to weth and then to ald
    uint256 wethAmount;
    if (token == weth) {
      wethAmount = amount;
    } else {
      require(toWETH[toWETH.length - 1] == weth, "POLExecutor: invalid toUSDC path");
      wethAmount = _swapTo(token, amount, router, toWETH);
    }
    if (wethAmount > 0) {
      aldAmount = aldAmount.add(_swapToALD(aldweth, weth, wethAmount));
    }

    require(aldAmount >= minALDAmount, "POLExecutor: not enough ald amount");
  }

  /// @dev Withdraw token from treasury, swap and add liquidity
  /// @param token The address of token to withdraw.
  /// @param amount The amount of token to withdraw.
  /// @param router The address of router to use, usually uniswap or sushiswap.
  /// @param toUSDC The path from token to USDC.
  /// @param toWETH The path from token to WETH.
  /// @param minALDUSDCLP The minimum amount of ALD USDC LP should get.
  /// @param minALDWETHLP The minimum amount of ALD USDC LP should get.
  function withdrawAndSwapToLP(
    address token,
    uint256 amount,
    address router,
    address[] calldata toUSDC,
    address[] calldata toWETH,
    uint256 minALDUSDCLP,
    uint256 minALDWETHLP
  ) external onlyWhitelist {
    require(whitelist[msg.sender], "POLExecutor: only whitelist");
    ITreasury(treasury).withdraw(token, amount);

    // swap to usdc and then to aldusdc lp
    uint256 usdcAmount;
    if (token == usdc) {
      usdcAmount = amount / 2;
    } else {
      require(toUSDC[toUSDC.length - 1] == usdc, "POLExecutor: invalid toUSDC path");
      usdcAmount = _swapTo(token, amount / 2, router, toUSDC);
    }
    amount = amount - amount / 2;
    if (usdcAmount > 0) {
      uint256 lpAmount = _swapToLP(aldusdc, usdc, usdcAmount);
      require(lpAmount >= minALDUSDCLP, "not enough ALDUSDC LP");
    }

    // swap to weth and then to aldweth lp
    uint256 wethAmount;
    if (token == weth) {
      wethAmount = amount;
    } else {
      require(toWETH[toWETH.length - 1] == weth, "POLExecutor: invalid toUSDC path");
      wethAmount = _swapTo(token, amount, router, toWETH);
    }
    if (wethAmount > 0) {
      uint256 lpAmount = _swapToLP(aldweth, weth, wethAmount);
      require(lpAmount >= minALDWETHLP, "not enough ALDWETH LP");
    }
  }

  /// @dev Withdraw ALD from treasury, swap and add liquidity.
  /// @param amount The amount of ald token to withdraw.
  /// @param minALDUSDCLP The minimum amount of ALD USDC LP should get.
  /// @param minALDWETHLP The minimum amount of ALD USDC LP should get.
  function withdrawALDAndSwapToLP(
    uint256 amount,
    uint256 minALDUSDCLP,
    uint256 minALDWETHLP
  ) external onlyWhitelist {
    require(whitelist[msg.sender], "POLExecutor: only whitelist");
    ITreasury(treasury).manage(ald, amount);

    uint256 aldusdcAmount = _swapToLP(aldusdc, ald, amount / 2);
    require(aldusdcAmount >= minALDUSDCLP, "POLExecutor: not enough ALDUSDC LP");

    uint256 aldwethAmount = _swapToLP(aldweth, ald, amount - amount / 2);
    require(aldwethAmount >= minALDWETHLP, "POLExecutor: not enough ALDWETH LP");
  }

  /// @dev Withdraw ALD and token from treasury, and then add liquidity.
  /// @param aldAmount The amount of ald token to withdraw.
  /// @param token The address of other token, should be usdc or weth.
  /// @param minLPAmount The minimum lp amount should get.
  function withdrawAndAddLiquidity(
    uint256 aldAmount,
    address token,
    uint256 minLPAmount
  ) external onlyWhitelist {
    address pair;
    uint256 reserve0;
    uint256 reserve1;
    if (token == usdc) {
      (reserve0, reserve1, ) = IUniswapV2Pair(aldusdc).getReserves();
      pair = aldusdc;
    } else if (token == weth) {
      (reserve0, reserve1, ) = IUniswapV2Pair(aldweth).getReserves();
      pair = aldweth;
    } else {
      revert("POLExecutor: token not supported");
    }
    if (ald > token) {
      (reserve0, reserve1) = (reserve1, reserve0);
    }
    uint256 tokenAmount = aldAmount.mul(reserve1).div(reserve0);

    ITreasury(treasury).manage(ald, aldAmount);
    ITreasury(treasury).withdraw(token, tokenAmount);
    IERC20(ald).safeTransfer(pair, aldAmount);
    IERC20(token).safeTransfer(pair, tokenAmount);

    uint256 lpAmount = IUniswapV2Pair(pair).mint(treasury);
    require(lpAmount >= minLPAmount, "POLExecutor: not enough lp");
  }

  function _ensureAllowance(
    address token,
    address spender,
    uint256 amount
  ) internal {
    if (IERC20(token).allowance(address(this), spender) < amount) {
      IERC20(token).safeApprove(spender, 0);
      IERC20(token).safeApprove(spender, amount);
    }
  }

  function _swapTo(
    address token,
    uint256 amount,
    address router,
    address[] memory path
  ) internal returns (uint256) {
    require(path.length >= 2 && path[0] == token, "POLExecutor: invalid swap path");
    _ensureAllowance(token, router, amount);
    uint256[] memory amounts = IUniswapV2Router(router).swapExactTokensForTokens(
      amount,
      0,
      path,
      address(this),
      block.timestamp
    );
    return amounts[amounts.length - 1];
  }

  function _swapToALD(
    address pair,
    address token,
    uint256 amount
  ) internal returns (uint256) {
    uint256 rIn;
    uint256 rOut;
    if (ald < token) {
      (rOut, rIn, ) = IUniswapV2Pair(pair).getReserves();
    } else {
      (rIn, rOut, ) = IUniswapV2Pair(pair).getReserves();
    }
    uint256 amountWithFee = amount.mul(997);
    uint256 output = rOut.mul(amountWithFee).div(rIn.mul(1000).add(amountWithFee));
    IERC20(token).safeTransfer(pair, amount);
    if (ald < token) {
      IUniswapV2Pair(pair).swap(output, 0, treasury, new bytes(0));
    } else {
      IUniswapV2Pair(pair).swap(0, output, treasury, new bytes(0));
    }
    return output;
  }

  function _swapToLP(
    address pair,
    address token,
    uint256 amount
  ) internal returns (uint256) {
    // first swap some part of token to other token.
    uint256 rIn;
    uint256 rOut;
    address token0 = IUniswapV2Pair(pair).token0();
    address token1 = IUniswapV2Pair(pair).token1();
    if (token0 == token) {
      (rIn, rOut, ) = IUniswapV2Pair(pair).getReserves();
    } else {
      (rOut, rIn, ) = IUniswapV2Pair(pair).getReserves();
    }
    // (amount - x) : x * rOut * 997 / (rIn * 1000 + 997 * x) = (rIn + amount) : rOut
    // => 997 * x^2 + 1997 * rIn * x - rIn * amount * 1000 = 0
    // => x = (sqrt(rIn^2 * 3988009 + 3988000 * amount * rIn) - 1997 * rIn) / 1994
    uint256 swapAmount = Babylonian.sqrt(rIn.mul(amount.mul(3988000).add(rIn.mul(3988009)))).sub(rIn.mul(1997)) / 1994;
    uint256 amountWithFee = swapAmount.mul(997);
    uint256 output = rOut.mul(amountWithFee).div(rIn.mul(1000).add(amountWithFee));
    IERC20(token).safeTransfer(pair, swapAmount);
    if (token0 == token) {
      IUniswapV2Pair(pair).swap(0, output, address(this), new bytes(0));
      IERC20(token1).safeTransfer(pair, output);
    } else {
      IUniswapV2Pair(pair).swap(output, 0, address(this), new bytes(0));
      IERC20(token0).safeTransfer(pair, output);
    }

    // then add liquidity
    IERC20(token).safeTransfer(pair, amount.sub(swapAmount));
    return IUniswapV2Pair(pair).mint(treasury);
  }
}