// Sources flattened with hardhat v2.4.3 https://hardhat.org

// File @openzeppelin/contracts/token/ERC20/IERC20.sol@v3.1.0

// SPDX-License-Identifier: MIT

pragma solidity ^0.6.0;

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


// File @openzeppelin/contracts/math/SafeMath.sol@v3.1.0


pragma solidity ^0.6.0;

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


// File @openzeppelin/contracts/utils/Address.sol@v3.1.0


pragma solidity ^0.6.2;

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
        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);
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


// File @openzeppelin/contracts/token/ERC20/SafeERC20.sol@v3.1.0


pragma solidity ^0.6.0;



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


// File @openzeppelin/contracts/utils/EnumerableSet.sol@v3.1.0


pragma solidity ^0.6.0;

/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * As of v3.0.0, only sets of type `address` (`AddressSet`) and `uint256`
 * (`UintSet`) are supported.
 */
library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;

        // Position of the value in the `values` array, plus 1 because index 0
        // means a value is not in the set.
        mapping (bytes32 => uint256) _indexes;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We read and store the value's index to prevent multiple reads from the same storage slot
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) { // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            // When the value to delete is the last one, the swap operation is unnecessary. However, since this occurs
            // so rarely, we still do the swap anyway to avoid the gas cost of adding an 'if' statement.

            bytes32 lastvalue = set._values[lastIndex];

            // Move the last value to the index where the value to delete is
            set._values[toDeleteIndex] = lastvalue;
            // Update the index for the moved value
            set._indexes[lastvalue] = toDeleteIndex + 1; // All indexes are 1-based

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the index for the deleted slot
            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._indexes[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        require(set._values.length > index, "EnumerableSet: index out of bounds");
        return set._values[index];
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(value)));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(value)));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(value)));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint256(_at(set._inner, index)));
    }


    // UintSet

    struct UintSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }
}


// File @openzeppelin/contracts/GSN/Context.sol@v3.1.0

pragma solidity ^0.6.0;

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


// File @openzeppelin/contracts/access/Ownable.sol@v3.1.0


pragma solidity ^0.6.0;

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
contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
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
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
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


// File contracts/sone-smart-contracts/interfaces/ISoneToken.sol

pragma solidity 0.6.12;

interface ISoneToken {
	event Lock(address indexed to, uint256 value);

	event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

	event WhitelistAdded(address indexed account);
	event WhitelistRemoved(address indexed account);
	event WhitelistRevoked(address indexed account);

	function allowTransferOn() external view returns (uint256);

	function lockFromBlock() external view returns (uint256);

	function lockToBlock() external view returns (uint256);

	function circulatingSupply() external view returns (uint256);

	function totalLock() external view returns (uint256);

	function mint(address _to, uint256 _amount) external;

	function totalBalanceOf(address _holder) external view returns (uint256);

	function lockOf(address _holder) external view returns (uint256);

	function lastUnlockBlock(address _holder) external view returns (uint256);

	function lock(address _holder, uint256 _amount) external;

	function canUnlockAmount(address _holder) external view returns (uint256);

	function unlock() external;

	function transferAll(address _to) external;

	function setLockFromBlock(uint256 lockFromBlock_) external;

	function setLockToBlock(uint256 lockToBlock_) external;

	function setAllowTransferOn(uint256 allowTransferOn_) external;

	function name() external view returns (string memory);

	function symbol() external view returns (string memory);

	function decimals() external view returns (uint8);

	function totalSupply() external view returns (uint256);

	function balanceOf(address account) external view returns (uint256);

	function transfer(address recipient, uint256 amount) external returns (bool);

	function allowance(address owner, address spender) external view returns (uint256);

	function approve(address spender, uint256 amount) external returns (bool);

	function transferFrom(
		address sender,
		address recipient,
		uint256 amount
	) external returns (bool);

	function increaseAllowance(address spender, uint256 addedValue) external returns (bool);

	function decreaseAllowance(address spender, uint256 subtractedValue) external returns (bool);

	function cap() external view returns (uint256);

	function burn(uint256 amount) external;

	function burnFrom(address account, uint256 amount) external;

	function transferOwnership(address newOwner) external;

	function owner() external view returns (address);

	function renounceOwnership() external;

	function isWhitelist(address account) external view returns (bool);

	function addWhitelist(address account) external;

	function renounceWhitelist() external;

	function revokeWhitelist(address account_) external;
}


// File contracts/sone-smart-contracts/SoneMasterFarmer.sol

// SoneMasterFarmer
pragma solidity 0.6.12;






interface IMigratorToSoneSwap {
	// Perform LP token migration from legacy UniswapV2 to SoneSwap.
	// Take the current LP token address and return the new LP token address.
	// Migrator should have full access to the caller's LP token.
	// Return the new LP token address.
	//
	// XXX Migrator must have allowance access to UniswapV2 LP tokens.
	// SoneSwap must mint EXACTLY the same amount of SoneSwap LP tokens or
	// else something bad will happen. Traditional UniswapV2 does not
	// do that so be careful!
	function migrate(IERC20 token) external returns (IERC20);
}

// SoneMasterFarmer is the master of SONE. He can make SONE and he is a fair guy.
//
// Note that it's ownable and the owner wields tremendous power. The ownership
// will be transferred to a governance smart contract once SONE is sufficiently
// distributed and the community can show to govern itself.
//
// Have fun reading it. Hopefully it's bug-free. God bless.
contract SoneMasterFarmer is Ownable {
	using SafeMath for uint256;
	using SafeERC20 for IERC20;

	// Info of each user.
	struct UserInfo {
		uint256 amount; // How many LP tokens the user has provided.
		uint256 rewardDebt; // Reward debt. See explanation below.
		uint256 rewardDebtAtBlock; // the last block user stake
		//
		// We do some fancy math here. Basically, any point in time, the amount of SONEs
		// entitled to a user but is pending to be distributed is:
		//
		//   pending reward = (user.amount * pool.accSonePerShare) - user.rewardDebt
		//
		// Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:
		//   1. The pool's `accSonePerShare` (and `lastRewardBlock`) gets updated.
		//   2. User receives the pending reward sent to his/her address.
		//   3. User's `amount` gets updated.
		//   4. User's `rewardDebt` gets updated.
	}

	// Info of each pool.
	struct PoolInfo {
		IERC20 lpToken; // Address of LP token contract.
		uint256 allocPoint; // How many allocation points assigned to this pool. SONEs to distribute per block.
		uint256 lastRewardBlock; // Last block number that SONEs distribution occurs.
		uint256 accSonePerShare; // Accumulated SONEs per share, times 1e12. See below.
	}

	// The SONE TOKEN!
	ISoneToken public sone;
	// Dev address.
	address public devaddr;
	// SONE tokens created per block.
	uint256 public REWARD_PER_BLOCK;
	// Bonus multiplier for early SONE makers.
	uint256[] public REWARD_MULTIPLIER = [32, 32, 32, 32, 16, 8, 4, 2, 1];
	uint256[] public HALVING_AT_BLOCK; // init in constructor function
	uint256 public FINISH_BONUS_AT_BLOCK;

	// The block number when SONE mining starts.
	uint256 public START_BLOCK;

	uint256 public constant PERCENT_LOCK_BONUS_REWARD = 75; // lock 75% of bonus reward in 1 year
	uint256 public constant PERCENT_FOR_DEV = 10; // 10% reward for dev

	// The migrator contract. It has a lot of power. Can only be set through governance (owner).
	IMigratorToSoneSwap public migrator;

	// Info of each pool.
	PoolInfo[] public poolInfo;
	mapping(address => uint256) public poolId1; // poolId1 count from 1, subtraction 1 before using with poolInfo
	// Info of each user that stakes LP tokens. pid => user address => info
	mapping(uint256 => mapping(address => UserInfo)) public userInfo;
	// Total allocation points. Must be the sum of all allocation points in all pools.
	uint256 public totalAllocPoint = 0;

	event Add(uint256 allocPoint, address lpToken, bool withUpdate);
	event Set(uint256 indexed pid, uint256 allocPoint, bool withUpdate);
	event SetMigrator(address migrator);
	event Migrate(uint256 indexed pid);
	event UpdatePool(uint256 indexed pid);
	event Dev(address devaddr);

	event Deposit(address indexed user, uint256 indexed pid, uint256 amount);
	event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);
	event EmergencyWithdraw(address indexed user, uint256 indexed pid, uint256 amount);
	event SendSoneReward(address indexed user, uint256 indexed pid, uint256 amount, uint256 lockAmount);

	constructor(
		ISoneToken _sone,
		address _devaddr,
		uint256 _rewardPerBlock,
		uint256 _startBlock,
		uint256 _halvingAfterBlock
	) public {
		sone = _sone;
		devaddr = _devaddr;
		REWARD_PER_BLOCK = _rewardPerBlock;
		START_BLOCK = _startBlock;
		for (uint256 i = 0; i < REWARD_MULTIPLIER.length - 1; i++) {
			uint256 halvingAtBlock = _halvingAfterBlock.mul(i + 1).add(_startBlock);
			HALVING_AT_BLOCK.push(halvingAtBlock);
		}
		FINISH_BONUS_AT_BLOCK = _halvingAfterBlock.mul(REWARD_MULTIPLIER.length - 1).add(_startBlock);
		HALVING_AT_BLOCK.push(uint256(-1));
	}

	function poolLength() external view returns (uint256) {
		return poolInfo.length;
	}

	// Add a new lp to the pool. Can only be called by the owner.
	function add(
		uint256 _allocPoint,
		IERC20 _lpToken,
		bool _withUpdate
	) public onlyOwner {
		require(poolId1[address(_lpToken)] == 0, "SoneMasterFarmer::add: lp is already in pool");
		if (_withUpdate) {
			massUpdatePools();
		}
		uint256 lastRewardBlock = block.number > START_BLOCK ? block.number : START_BLOCK;
		totalAllocPoint = totalAllocPoint.add(_allocPoint);
		poolId1[address(_lpToken)] = poolInfo.length + 1;
		poolInfo.push(PoolInfo({lpToken: _lpToken, allocPoint: _allocPoint, lastRewardBlock: lastRewardBlock, accSonePerShare: 0}));
		emit Add(_allocPoint, address(_lpToken), _withUpdate);
	}

	// Update the given pool's SONE allocation point. Can only be called by the owner.
	function set(
		uint256 _pid,
		uint256 _allocPoint,
		bool _withUpdate
	) public onlyOwner {
		if (_withUpdate) {
			massUpdatePools();
		}
		totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(_allocPoint);
		poolInfo[_pid].allocPoint = _allocPoint;
		emit Set(_pid, _allocPoint, _withUpdate);
	}

	// Set the migrator contract. Can only be called by the owner.
	function setMigrator(IMigratorToSoneSwap _migrator) public onlyOwner {
		migrator = _migrator;
		emit SetMigrator(address(_migrator));
	}

	// Migrate lp token to another lp contract. Can be called by anyone. We trust that migrator contract is good.
	function migrate(uint256 _pid) public {
		require(address(migrator) != address(0), "migrate: no migrator");
		PoolInfo storage pool = poolInfo[_pid];
		IERC20 lpToken = pool.lpToken;
		uint256 bal = lpToken.balanceOf(address(this));
		lpToken.safeApprove(address(migrator), bal);
		IERC20 newLpToken = migrator.migrate(lpToken);
		require(bal == newLpToken.balanceOf(address(this)), "migrate: bad");
		pool.lpToken = newLpToken;
		emit Migrate(_pid);
	}

	// Update reward variables for all pools. Be careful of gas spending!
	function massUpdatePools() public {
		uint256 length = poolInfo.length;
		for (uint256 pid = 0; pid < length; ++pid) {
			updatePool(pid);
		}
	}

	// Update reward variables of the given pool to be up-to-date.
	function updatePool(uint256 _pid) public {
		PoolInfo storage pool = poolInfo[_pid];
		if (block.number <= pool.lastRewardBlock) {
			return;
		}
		uint256 lpSupply = pool.lpToken.balanceOf(address(this));
		if (lpSupply == 0) {
			pool.lastRewardBlock = block.number;
			return;
		}
		uint256 soneForDev;
		uint256 soneForFarmer;
		(soneForDev, soneForFarmer) = getPoolReward(pool.lastRewardBlock, block.number, pool.allocPoint);

		if (soneForDev > 0) {
			sone.mint(devaddr, soneForDev);
			// For more simple, I lock reward for dev if mint reward in bonus time
			if (block.number <= FINISH_BONUS_AT_BLOCK) {
				sone.lock(devaddr, soneForDev.mul(PERCENT_LOCK_BONUS_REWARD).div(100));
			}
		}
		sone.mint(address(this), soneForFarmer);
		pool.accSonePerShare = pool.accSonePerShare.add(soneForFarmer.mul(1e12).div(lpSupply));
		pool.lastRewardBlock = block.number;
		emit UpdatePool(_pid);
	}

	// |--------------------------------------|
	// [20, 30, 40, 50, 60, 70, 80, 99999999]
	// Return reward multiplier over the given _from to _to block.
	function getMultiplier(uint256 _from, uint256 _to) public view returns (uint256) {
		uint256 result = 0;
		if (_from < START_BLOCK) return 0;

		for (uint256 i = 0; i < HALVING_AT_BLOCK.length; i++) {
			uint256 endBlock = HALVING_AT_BLOCK[i];

			if (_to <= endBlock) {
				uint256 m = _to.sub(_from).mul(REWARD_MULTIPLIER[i]);
				return result.add(m);
			}

			if (_from < endBlock) {
				uint256 m = endBlock.sub(_from).mul(REWARD_MULTIPLIER[i]);
				_from = endBlock;
				result = result.add(m);
			}
		}

		return result;
	}

	function getPoolReward(
		uint256 _from,
		uint256 _to,
		uint256 _allocPoint
	) public view returns (uint256 forDev, uint256 forFarmer) {
		uint256 multiplier = getMultiplier(_from, _to);
		uint256 amount = multiplier.mul(REWARD_PER_BLOCK).mul(_allocPoint).div(totalAllocPoint);
		uint256 soneCanMint = sone.cap().sub(sone.totalSupply());

		if (soneCanMint < amount) {
			forDev = 0;
			forFarmer = soneCanMint;
		} else {
			if (soneCanMint < amount.mul(PERCENT_FOR_DEV + 100).div(100)) {
				forDev = 0;
				forFarmer = amount;
			} else {
				forDev = amount.mul(PERCENT_FOR_DEV).div(100);
				forFarmer = amount;
			}
		}
	}

	// View function to see pending SONEs on frontend.
	function pendingReward(uint256 _pid, address _user) external view returns (uint256) {
		PoolInfo storage pool = poolInfo[_pid];
		UserInfo storage user = userInfo[_pid][_user];
		uint256 accSonePerShare = pool.accSonePerShare;
		uint256 lpSupply = pool.lpToken.balanceOf(address(this));
		if (block.number > pool.lastRewardBlock && lpSupply > 0) {
			uint256 soneForFarmer;
			(, soneForFarmer) = getPoolReward(pool.lastRewardBlock, block.number, pool.allocPoint);
			accSonePerShare = accSonePerShare.add(soneForFarmer.mul(1e12).div(lpSupply));
		}
		return user.amount.mul(accSonePerShare).div(1e12).sub(user.rewardDebt);
	}

	function claimReward(uint256 _pid) public {
		updatePool(_pid);
		_harvest(_pid);
	}

	// lock 75% of reward if it come from bonus time
	function _harvest(uint256 _pid) internal {
		PoolInfo storage pool = poolInfo[_pid];
		UserInfo storage user = userInfo[_pid][msg.sender];

		if (user.amount > 0) {
			uint256 pending = user.amount.mul(pool.accSonePerShare).div(1e12).sub(user.rewardDebt);
			uint256 masterBal = sone.balanceOf(address(this));
			uint256 lockAmount = 0;

			if (pending > masterBal) {
				pending = masterBal;
			}

			if (pending > 0) {
				sone.transfer(msg.sender, pending);
				if (user.rewardDebtAtBlock <= FINISH_BONUS_AT_BLOCK) {
					lockAmount = pending.mul(PERCENT_LOCK_BONUS_REWARD).div(100);
					sone.lock(msg.sender, lockAmount);
				}

				user.rewardDebtAtBlock = block.number;
			}

			user.rewardDebt = user.amount.mul(pool.accSonePerShare).div(1e12);
			emit SendSoneReward(msg.sender, _pid, pending, lockAmount);
		}
	}

	// Deposit LP tokens to SoneMasterFarmer for SONE allocation.
	function deposit(uint256 _pid, uint256 _amount) public {
		require(_amount > 0, "SoneMasterFarmer::deposit: amount must be greater than 0");

		PoolInfo storage pool = poolInfo[_pid];
		UserInfo storage user = userInfo[_pid][msg.sender];
		updatePool(_pid);
		_harvest(_pid);
		pool.lpToken.safeTransferFrom(address(msg.sender), address(this), _amount);
		if (user.amount == 0) {
			user.rewardDebtAtBlock = block.number;
		}
		user.amount = user.amount.add(_amount);
		user.rewardDebt = user.amount.mul(pool.accSonePerShare).div(1e12);
		emit Deposit(msg.sender, _pid, _amount);
	}

	// Withdraw LP tokens from SoneMasterFarmer.
	function withdraw(uint256 _pid, uint256 _amount) public {
		PoolInfo storage pool = poolInfo[_pid];
		UserInfo storage user = userInfo[_pid][msg.sender];
		require(user.amount >= _amount, "SoneMasterFarmer::withdraw: not good");

		updatePool(_pid);
		_harvest(_pid);

		if (_amount > 0) {
			user.amount = user.amount.sub(_amount);
			pool.lpToken.safeTransfer(address(msg.sender), _amount);
		}
		user.rewardDebt = user.amount.mul(pool.accSonePerShare).div(1e12);
		emit Withdraw(msg.sender, _pid, _amount);
	}

	// Withdraw without caring about rewards. EMERGENCY ONLY.
	function emergencyWithdraw(uint256 _pid) public {
		PoolInfo storage pool = poolInfo[_pid];
		UserInfo storage user = userInfo[_pid][msg.sender];
		pool.lpToken.safeTransfer(address(msg.sender), user.amount);
		emit EmergencyWithdraw(msg.sender, _pid, user.amount);
		user.amount = 0;
		user.rewardDebt = 0;
	}

	// Safe sone transfer function, just in case if rounding error causes pool to not have enough SONEs.
	function safeSoneTransfer(address _to, uint256 _amount) internal {
		uint256 soneBal = sone.balanceOf(address(this));
		if (_amount > soneBal) {
			sone.transfer(_to, soneBal);
		} else {
			sone.transfer(_to, _amount);
		}
	}

	// Update dev address by the previous dev.
	function dev(address _devaddr) public {
		require(msg.sender == devaddr, "dev: wut?");
		devaddr = _devaddr;
		emit Dev(_devaddr);
	}

	function getNewRewardPerBlock(uint256 pid1) public view returns (uint256) {
		uint256 multiplier = getMultiplier(block.number - 1, block.number);
		if (pid1 == 0) {
			return multiplier.mul(REWARD_PER_BLOCK);
		} else {
			return multiplier.mul(REWARD_PER_BLOCK).mul(poolInfo[pid1 - 1].allocPoint).div(totalAllocPoint);
		}
	}

	// mint SONE token via MasterFarmer
	function mintSoneToken(address account, uint256 amount) public onlyOwner {
		sone.mint(account, amount);
	}

	// transfer ownership SONE token
	function transferOwnershipSoneToken(address newOwner) public onlyOwner {
		sone.transferOwnership(newOwner);
	}
}