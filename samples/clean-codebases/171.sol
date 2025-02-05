pragma solidity 0.6.12;

interface IERC1820Registry {

    /**

     * @dev Sets `newManager` as the manager for `account`. A manager of an

     * account is able to set interface implementers for it.

     *

     * By default, each account is its own manager. Passing a value of `0x0` in

     * `newManager` will reset the manager to this initial state.

     *

     * Emits a {ManagerChanged} event.

     *

     * Requirements:

     *

     * - the caller must be the current manager for `account`.

     */

    function setManager(address account, address newManager) external;



    /**

     * @dev Returns the manager for `account`.

     *

     * See {setManager}.

     */

    function getManager(address account) external view returns (address);



    /**

     * @dev Sets the `implementer` contract as ``account``'s implementer for

     * `interfaceHash`.

     *

     * `account` being the zero address is an alias for the caller's address.

     * The zero address can also be used in `implementer` to remove an old one.

     *

     * See {interfaceHash} to learn how these are created.

     *

     * Emits an {InterfaceImplementerSet} event.

     *

     * Requirements:

     *

     * - the caller must be the current manager for `account`.

     * - `interfaceHash` must not be an {IERC165} interface id (i.e. it must not

     * end in 28 zeroes).

     * - `implementer` must implement {IERC1820Implementer} and return true when

     * queried for support, unless `implementer` is the caller. See

     * {IERC1820Implementer-canImplementInterfaceForAddress}.

     */

    function setInterfaceImplementer(address account, bytes32 interfaceHash, address implementer) external;



    /**

     * @dev Returns the implementer of `interfaceHash` for `account`. If no such

     * implementer is registered, returns the zero address.

     *

     * If `interfaceHash` is an {IERC165} interface id (i.e. it ends with 28

     * zeroes), `account` will be queried for support of it.

     *

     * `account` being the zero address is an alias for the caller's address.

     */

    function getInterfaceImplementer(address account, bytes32 interfaceHash) external view returns (address);



    /**

     * @dev Returns the interface hash for an `interfaceName`, as defined in the

     * corresponding

     * https://eips.ethereum.org/EIPS/eip-1820#interface-name[section of the EIP].

     */

    function interfaceHash(string calldata interfaceName) external pure returns (bytes32);



    /**

     *  @notice Updates the cache with whether the contract implements an ERC165 interface or not.

     *  @param account Address of the contract for which to update the cache.

     *  @param interfaceId ERC165 interface for which to update the cache.

     */

    function updateERC165Cache(address account, bytes4 interfaceId) external;



    /**

     *  @notice Checks whether a contract implements an ERC165 interface or not.

     *  If the result is not cached a direct lookup on the contract address is performed.

     *  If the result is not cached or the cached value is out-of-date, the cache MUST be updated manually by calling

     *  {updateERC165Cache} with the contract address.

     *  @param account Address of the contract to check.

     *  @param interfaceId ERC165 interface to check.

     *  @return True if `account` implements `interfaceId`, false otherwise.

     */

    function implementsERC165Interface(address account, bytes4 interfaceId) external view returns (bool);



    /**

     *  @notice Checks whether a contract implements an ERC165 interface or not without using nor updating the cache.

     *  @param account Address of the contract to check.

     *  @param interfaceId ERC165 interface to check.

     *  @return True if `account` implements `interfaceId`, false otherwise.

     */

    function implementsERC165InterfaceNoCache(address account, bytes4 interfaceId) external view returns (bool);



    event InterfaceImplementerSet(address indexed account, bytes32 indexed interfaceHash, address indexed implementer);



    event ManagerChanged(address indexed account, address indexed newManager);

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

interface IERC777Recipient {

    /**

     * @dev Called by an {IERC777} token contract whenever tokens are being

     * moved or created into a registered account (`to`). The type of operation

     * is conveyed by `from` being the zero address or not.

     *

     * This call occurs _after_ the token contract's state is updated, so

     * {IERC777-balanceOf}, etc., can be used to query the post-operation state.

     *

     * This function may revert to prevent the operation from being executed.

     */

    function tokensReceived(

        address operator,

        address from,

        address to,

        uint256 amount,

        bytes calldata userData,

        bytes calldata operatorData

    ) external;

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

interface HermezVesting {

    function move(address recipient, uint256 amount) external;

    function changeAddress(address newAddress) external;

}

interface HEZ {

    function approve(address spender, uint256 amount) external returns (bool);

    function balanceOf(address account) external view returns (uint256);

    function transfer(address recipient, uint256 amount) external returns (bool);

}

contract BootstrapDistribution {

    using SafeMath for uint256;



    HEZ public constant TOKEN_ADDRESS = HEZ(0xEEF9f339514298C6A857EfCfC1A762aF84438dEE);

    HermezVesting public constant VESTING_0 = HermezVesting(0x8109dfB06D4d9e694a8349B855cBF493A0B22186);

    HermezVesting public constant VESTING_1 = HermezVesting(0xDd90cA911a5dbfB1624fF7Eb586901a9b4BFC53D);

    HermezVesting public constant VESTING_2 = HermezVesting(0xB213aeAeF76f82e42263fe896433A260EF018df2);

    HermezVesting public constant VESTING_3 = HermezVesting(0x3049399e1308db7d2b28488880C6cFE9Aa003275);

    address public constant MULTISIG_VESTING_2  = 0xC21BE548060cB6E07017bFc0b926A71b5E638e09;

    address public constant MULTISIG_VESTING_3  = 0x5Fa543E23a1B62e45d010f81AFC0602456BD1F1d;

    address public constant VESTING_0_ADDRESS_0 = 0x94E886bB17451A7B82E594db12570a5AdFC2D453;

    address public constant VESTING_0_ADDRESS_1 = 0x4FE10B3e306aC1F4b966Db07f031ae5780BC48fB;

    address public constant VESTING_0_ADDRESS_2 = 0x6629300128CCdda1e88641Ba2941a22Ce82F5df9;

    address public constant VESTING_0_ADDRESS_3 = 0xEb60e28Ce3aCa617d1E0293791c1903cF022b9Cd;

    address public constant VESTING_0_ADDRESS_4 = 0x9a415E0cE643abc4AD953B651b2D7e4db2FF3bEa;

    address public constant VESTING_0_ADDRESS_5 = 0x15b54c53093aF3e11d787db86e268a6C4F2F72A2;

    address public constant VESTING_0_ADDRESS_6 = 0x3279c71F132833190F6cd1D6a9975FFBf8d7C6dC;

    address public constant VESTING_0_ADDRESS_7 = 0x312e6f33155177774CDa1A3C4e9f077D93266063;

    address public constant VESTING_0_ADDRESS_8 = 0x47690A724Ed551fe2ff1A5eBa335B7c1B7a40990;

    address public constant VESTING_1_ADDRESS_0 = 0x80FbB6dd386FC98D2B387F37845A373c8441c069;

    address public constant VESTING_2_ADDRESS_0 = 0xBd48F607E26d94772FB21ED1d814F9F116dBD95C;

    address public constant VESTING_3_ADDRESS_0 = 0x520Cf70a2D0B3dfB7386A2Bc9F800321F62a5c3a;

    address public constant NO_VESTED_ADDRESS_0 = 0x4D4a7675CC0eb0a3B1d81CbDcd828c4BD0D74155;

    address public constant NO_VESTED_ADDRESS_1 = 0x9CdaeBd2bcEED9EB05a3B3cccd601A40CB0026be;

    address public constant NO_VESTED_ADDRESS_2 = 0x9315F815002d472A3E993ac9dc7461f2601A3c09;

    address public constant NO_VESTED_ADDRESS_3 = 0xF96A39d61F6972d8dC0CCd2A3c082eD922E096a7;

    address public constant NO_VESTED_ADDRESS_4 = 0xA93Bb239509D16827B7ee9DA7dA6Fc8478837247;

    address public constant NO_VESTED_ADDRESS_5 = 0x99Ae889E171B82BB04FD22E254024716932e5F2f;

    uint256 public constant VESTING_0_AMOUNT            = 20_000_000 ether;

    uint256 public constant VESTING_1_AMOUNT            = 10_000_000 ether;

    uint256 public constant VESTING_2_AMOUNT            =  6_200_000 ether;

    uint256 public constant VESTING_3_AMOUNT            = 17_500_000 ether;    

    uint256 public constant VESTING_0_ADDRESS_0_AMOUNT  = 12_000_000 ether;

    uint256 public constant VESTING_0_ADDRESS_1_AMOUNT  =  1_850_000 ether;

    uint256 public constant VESTING_0_ADDRESS_2_AMOUNT  =  1_675_000 ether;

    uint256 public constant VESTING_0_ADDRESS_3_AMOUNT  =  1_300_000 ether;

    uint256 public constant VESTING_0_ADDRESS_4_AMOUNT  =  1_000_000 ether;

    uint256 public constant VESTING_0_ADDRESS_5_AMOUNT  =    750_000 ether;

    uint256 public constant VESTING_0_ADDRESS_6_AMOUNT  =    625_000 ether;

    uint256 public constant VESTING_0_ADDRESS_7_AMOUNT  =    525_000 ether;

    uint256 public constant VESTING_0_ADDRESS_8_AMOUNT  =    275_000 ether;

    uint256 public constant VESTING_1_ADDRESS_0_AMOUNT  = 10_000_000 ether;

    uint256 public constant VESTING_2_ADDRESS_0_AMOUNT  =    500_000 ether;

    uint256 public constant VESTING_3_ADDRESS_0_AMOUNT  =    300_000 ether;

    uint256 public constant NO_VESTED_ADDRESS_0_AMOUNT  = 19_000_000 ether;

    uint256 public constant NO_VESTED_ADDRESS_1_AMOUNT  =  9_000_000 ether;

    uint256 public constant NO_VESTED_ADDRESS_2_AMOUNT  =  7_500_000 ether;

    uint256 public constant NO_VESTED_ADDRESS_3_AMOUNT  =  5_000_000 ether;

    uint256 public constant NO_VESTED_ADDRESS_4_AMOUNT  =  3_000_000 ether;

    uint256 public constant NO_VESTED_ADDRESS_5_AMOUNT  =  2_800_000 ether;

    uint256 public constant INTERMEDIATE_BALANCE        = 46_300_000 ether;



    function distribute() public {

        require(

            TOKEN_ADDRESS.balanceOf(address(this)) == (100_000_000 ether), 

            "BootstrapDistribution::distribute NOT_ENOUGH_BALANCE"

        );



        // Vested Tokens

        // Transfer HEZ tokens

        TOKEN_ADDRESS.transfer(address(VESTING_0),VESTING_0_AMOUNT);

        TOKEN_ADDRESS.transfer(address(VESTING_1),VESTING_1_AMOUNT);

        TOKEN_ADDRESS.transfer(address(VESTING_2),VESTING_2_AMOUNT);

        TOKEN_ADDRESS.transfer(address(VESTING_3),VESTING_3_AMOUNT);

        // Transfer vested tokens

        transferVestedTokens0();

        transferVestedTokens1();

        transferVestedTokens2();

        transferVestedTokens3();



        // Check intermediate balance

        require(

            TOKEN_ADDRESS.balanceOf(address(this)) == INTERMEDIATE_BALANCE,

            "BootstrapDistribution::distribute NOT_ENOUGH_NO_VESTED_BALANCE"

        );



        // No Vested Tokens

        TOKEN_ADDRESS.transfer(NO_VESTED_ADDRESS_0, NO_VESTED_ADDRESS_0_AMOUNT);

        TOKEN_ADDRESS.transfer(NO_VESTED_ADDRESS_1, NO_VESTED_ADDRESS_1_AMOUNT);

        TOKEN_ADDRESS.transfer(NO_VESTED_ADDRESS_2, NO_VESTED_ADDRESS_2_AMOUNT);

        TOKEN_ADDRESS.transfer(NO_VESTED_ADDRESS_3, NO_VESTED_ADDRESS_3_AMOUNT);

        TOKEN_ADDRESS.transfer(NO_VESTED_ADDRESS_4, NO_VESTED_ADDRESS_4_AMOUNT);

        TOKEN_ADDRESS.transfer(NO_VESTED_ADDRESS_5, NO_VESTED_ADDRESS_5_AMOUNT);



        require(

            TOKEN_ADDRESS.balanceOf(address(this)) == 0, 

            "BootstrapDistribution::distribute PENDING_BALANCE"

        );

    }



    function transferVestedTokens0() internal {

        VESTING_0.move(VESTING_0_ADDRESS_0, VESTING_0_ADDRESS_0_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_1, VESTING_0_ADDRESS_1_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_2, VESTING_0_ADDRESS_2_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_3, VESTING_0_ADDRESS_3_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_4, VESTING_0_ADDRESS_4_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_5, VESTING_0_ADDRESS_5_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_6, VESTING_0_ADDRESS_6_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_7, VESTING_0_ADDRESS_7_AMOUNT);

        VESTING_0.move(VESTING_0_ADDRESS_8, VESTING_0_ADDRESS_8_AMOUNT);

        VESTING_0.changeAddress(address(0));

    }



    function transferVestedTokens1() internal {

        VESTING_1.move(VESTING_1_ADDRESS_0, VESTING_1_ADDRESS_0_AMOUNT);

        VESTING_1.changeAddress(address(0));

    }



    function transferVestedTokens2() internal {

        VESTING_2.move(VESTING_2_ADDRESS_0, VESTING_2_ADDRESS_0_AMOUNT);

        VESTING_2.changeAddress(MULTISIG_VESTING_2);    

    }



    function transferVestedTokens3() internal {

        VESTING_3.move(VESTING_3_ADDRESS_0, VESTING_3_ADDRESS_0_AMOUNT);

        VESTING_3.changeAddress(MULTISIG_VESTING_3);  

    }

}

contract HermezVesting {

    using SafeMath for uint256;



    address public distributor;



    mapping(address => uint256) public vestedTokens;

    mapping(address => uint256) public withdrawed;

    uint256 public totalVestedTokens;



    uint256 public startTime;

    uint256 public cliffTime;

    uint256 public endTime;

    uint256 public initialPercentage;



    address public constant HEZ = address(

        0xEEF9f339514298C6A857EfCfC1A762aF84438dEE

    );



    event Withdraw(address indexed recipient, uint256 amount);

    event Move(address indexed from, address indexed to, uint256 value);

    event ChangeAddress(address indexed oldAddress, address indexed newAddress);



    constructor(

        address _distributor,

        uint256 _totalVestedTokens,

        uint256 _startTime,

        uint256 _startToCliff,

        uint256 _startToEnd,

        uint256 _initialPercentage

    ) public {

        require(

            _startToEnd >= _startToCliff,

            "HermezVesting::constructor: START_GREATER_THAN_CLIFF"

        );

        require(

            _initialPercentage <= 100,

            "HermezVesting::constructor: INITIALPERCENTAGE_GREATER_THAN_100"

        );

        distributor = _distributor;

        totalVestedTokens = _totalVestedTokens;

        vestedTokens[_distributor] = _totalVestedTokens;

        startTime = _startTime;

        cliffTime = _startTime + _startToCliff;

        endTime = _startTime + _startToEnd;

        initialPercentage = _initialPercentage;

    }



    function totalTokensUnlockedAt(uint256 timestamp)

        public

        view

        returns (uint256)

    {

        if (timestamp < startTime) return 0;

        if (timestamp > endTime) return totalVestedTokens;



        uint256 initialAmount = totalVestedTokens.mul(initialPercentage).div(

            100

        );

        if (timestamp < cliffTime) return initialAmount;



        uint256 deltaT = timestamp.sub(startTime);

        uint256 deltaTTotal = endTime.sub(startTime);

        uint256 deltaAmountTotal = totalVestedTokens.sub(initialAmount);

        return initialAmount.add(deltaT.mul(deltaAmountTotal).div(deltaTTotal));

    }



    function withdrawableTokens(address recipient)

        public

        view

        returns (uint256)

    {

        return withdrawableTokensAt(recipient, block.timestamp);

    }



    function withdrawableTokensAt(address recipient, uint256 timestamp)

        public

        view

        returns (uint256)

    {

        uint256 unlockedAmount = totalTokensUnlockedAt(timestamp)

            .mul(vestedTokens[recipient])

            .div(totalVestedTokens);

        return unlockedAmount.sub(withdrawed[recipient]);

    }



    function withdraw() external {

        require(

            msg.sender != distributor,

            "HermezVesting::withdraw: DISTRIBUTOR_CANNOT_WITHDRAW"

        );



        uint256 remainingToWithdraw = withdrawableTokensAt(

            msg.sender,

            block.timestamp

        );



        withdrawed[msg.sender] = withdrawed[msg.sender].add(

            remainingToWithdraw

        );



        require(

            IERC20(HEZ).transfer(msg.sender, remainingToWithdraw),

            "HermezVesting::withdraw: TOKEN_TRANSFER_ERROR"

        );



        emit Withdraw(msg.sender, remainingToWithdraw);

    }



    function move(address recipient, uint256 amount) external {

        require(

            msg.sender == distributor,

            "HermezVesting::changeAddress: ONLY_DISTRIBUTOR"

        );

        vestedTokens[msg.sender] = vestedTokens[msg.sender].sub(amount);

        vestedTokens[recipient] = vestedTokens[recipient].add(amount);

        emit Move(msg.sender, recipient, amount);

    }



    function changeAddress(address newAddress) external {

        require(

            vestedTokens[newAddress] == 0,

            "HermezVesting::changeAddress: ADDRESS_HAS_BALANCE"

        );

        require(

            withdrawed[newAddress] == 0,

            "HermezVesting::changeAddress: ADDRESS_ALREADY_WITHDRAWED"

        );



        vestedTokens[newAddress] = vestedTokens[msg.sender];

        vestedTokens[msg.sender] = 0;

        withdrawed[newAddress] = withdrawed[msg.sender];

        withdrawed[msg.sender] = 0;



        if (msg.sender == distributor) {

            distributor = newAddress;

        }



        emit ChangeAddress(msg.sender, newAddress);

    }

}

contract LPTokenWrapper {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    // Uniswap v2 HEZ/ETH pair token

    IERC20 public UNI = IERC20(0x4a9EFa254085F36122d4b8BD2111544F8dC77052);



    uint256 private _totalSupply;

    mapping(address => uint256) private _balances;



    function totalSupply() public view returns (uint256) {

        return _totalSupply;

    }



    function balanceOf(address account) public view returns (uint256) {

        return _balances[account];

    }



    function stake(uint256 amount) public virtual {

        _totalSupply = _totalSupply.add(amount);

        _balances[msg.sender] = _balances[msg.sender].add(amount);

        UNI.safeTransferFrom(msg.sender, address(this), amount);

    }



    function withdraw(uint256 amount) public virtual {

        _totalSupply = _totalSupply.sub(amount);

        _balances[msg.sender] = _balances[msg.sender].sub(amount);

        UNI.safeTransfer(msg.sender, amount);

    }

}

contract Unipool is LPTokenWrapper, IERC777Recipient {

    uint256 public constant DURATION = 30 days;

    // Hermez Network Token

    IERC20 public HEZ = IERC20(0xcAEf929782361ccE9618c014D2867E423fE84ae7);



    IERC1820Registry private constant _ERC1820_REGISTRY = IERC1820Registry(

        0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24

    );

    bytes32 private constant _ERC777_RECIPIENT_INTERFACE_HASH = keccak256(

        "ERC777TokensRecipient"

    );



    uint256 public periodFinish;

    uint256 public rewardRate;

    uint256 public lastUpdateTime;

    uint256 public rewardPerTokenStored;

    mapping(address => uint256) public userRewardPerTokenPaid;

    mapping(address => uint256) public rewards;



    event RewardAdded(uint256 reward);

    event Staked(address indexed user, uint256 amount);

    event Withdrawn(address indexed user, uint256 amount);

    event RewardPaid(address indexed user, uint256 reward);



    modifier updateReward(address account) {

        rewardPerTokenStored = rewardPerToken();

        lastUpdateTime = lastTimeRewardApplicable();

        if (account != address(0)) {

            rewards[account] = earned(account);

            userRewardPerTokenPaid[account] = rewardPerTokenStored;

        }

        _;

    }



    constructor() public {

        _ERC1820_REGISTRY.setInterfaceImplementer(

            address(this),

            _ERC777_RECIPIENT_INTERFACE_HASH,

            address(this)

        );

    }



    function lastTimeRewardApplicable() public view returns (uint256) {

        return Math.min(block.timestamp, periodFinish);

    }



    function rewardPerToken() public view returns (uint256) {

        if (totalSupply() == 0) {

            return rewardPerTokenStored;

        }

        require(

            lastTimeRewardApplicable() >= lastUpdateTime,

            "lastTimeRewardApplicable < lastUpdateTime"

        );

        return

            rewardPerTokenStored.add(

                lastTimeRewardApplicable()

                    .sub(lastUpdateTime)

                    .mul(rewardRate)

                    .mul(1e18)

                    .div(totalSupply())

            );

    }



    function earned(address account) public view returns (uint256) {

        require(

            rewardPerToken() >= userRewardPerTokenPaid[account],

            "rewardPerToken() < userRewardPerTokenPaid[account] "

        );

        return

            balanceOf(account)

                .mul(rewardPerToken().sub(userRewardPerTokenPaid[account]))

                .div(1e18)

                .add(rewards[account]);

    }



    // stake visibility is public as overriding LPTokenWrapper's stake() function

    function stake(uint256 amount) public override updateReward(msg.sender) {

        require(amount > 0, "Cannot stake 0");

        super.stake(amount);

        emit Staked(msg.sender, amount);

    }



    function withdraw(uint256 amount) public override updateReward(msg.sender) {

        require(amount > 0, "Cannot withdraw 0");

        super.withdraw(amount);

        emit Withdrawn(msg.sender, amount);

    }



    function exit() external {

        withdraw(balanceOf(msg.sender));

        getReward();

    }



    function getReward() public updateReward(msg.sender) {

        uint256 reward = earned(msg.sender);

        if (reward > 0) {

            rewards[msg.sender] = 0;

            HEZ.safeTransfer(msg.sender, reward);

            emit RewardPaid(msg.sender, reward);

        }

    }



    function tokensReceived(

        // solhint-disable no-unused-vars

        address _operator,

        address _from,

        address _to,

        uint256 _amount,

        bytes calldata _userData,

        bytes calldata _operatorData

    ) external override updateReward(address(0)) {

        require(_amount > 0, "Cannot approve 0");

        require(msg.sender == address(HEZ), "Wrong token");

        require(

            _from == 0xF35960302a07022aBa880DFFaEC2Fdd64d5BF1c1,

            "Not allowed"

        );



        if (block.timestamp >= periodFinish) {

            rewardRate = _amount.div(DURATION);

        } else {

            uint256 remaining = periodFinish.sub(block.timestamp);

            uint256 leftover = remaining.mul(rewardRate);

            rewardRate = _amount.add(leftover).div(DURATION);

        }

        lastUpdateTime = block.timestamp;

        periodFinish = block.timestamp.add(DURATION);



        emit RewardAdded(_amount);

    }

}

interface IERC20 {

    function totalSupply() external view returns (uint256);



    function balanceOf(address account) external view returns (uint256);



    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



    function approve(address spender, uint256 amount) external returns (bool);



    function transfer(address recipient, uint256 amount)

        external

        returns (bool);



    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) external returns (bool);

}

library SafeMath {

    string private constant ERROR_ADD_OVERFLOW = "MATH:ADD_OVERFLOW";

    string private constant ERROR_SUB_UNDERFLOW = "MATH:SUB_UNDERFLOW";



    function add(uint256 x, uint256 y) internal pure returns (uint256 z) {

        require((z = x + y) >= x, ERROR_ADD_OVERFLOW);

    }



    function sub(uint256 x, uint256 y) internal pure returns (uint256 z) {

        require((z = x - y) <= x, ERROR_SUB_UNDERFLOW);

    }

}

contract HEZ is IERC20 {

    using SafeMath for uint256;



    uint8 public constant decimals = 18;    

    string public constant symbol = "HEZ";

    string public constant name = "Hermez Network Token";

    uint256 public constant initialBalance = 100_000_000 * (1e18);



    // bytes32 public constant PERMIT_TYPEHASH = 

    //      keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    bytes32 public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    // bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =

    //      keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");

    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // bytes32 public constant EIP712DOMAIN_HASH =

    //      keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")

    bytes32 public constant EIP712DOMAIN_HASH = 0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f;

    // bytes32 public constant NAME_HASH =

    //      keccak256("Hermez Network Token")

    bytes32 public constant NAME_HASH = 0x64c0a41a0260272b78f2a5bd50d5ff7c1779bc3bba16dcff4550c7c642b0e4b4;

    // bytes32 public constant VERSION_HASH =

    //      keccak256("1")

    bytes32 public constant VERSION_HASH = 0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6;



    uint256 public override totalSupply;

    mapping(address => uint256) public override balanceOf;

    mapping(address => mapping(address => uint256)) public override allowance;

    mapping(address => uint256) public nonces;

    mapping(address => mapping(bytes32 => bool)) public authorizationState;



    event Approval(address indexed owner, address indexed spender, uint256 value);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);



    constructor(address initialHolder) public {

        _mint(initialHolder, initialBalance);

    }



    function _validateSignedData(

        address signer,

        bytes32 encodeData,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) internal view {

        bytes32 domainSeparator = keccak256(

            abi.encode(

                EIP712DOMAIN_HASH,

                NAME_HASH,

                VERSION_HASH,

                getChainId(),

                address(this)

            )

        );



        bytes32 digest = keccak256(

            abi.encodePacked("\x19\x01", domainSeparator, encodeData)

        );

        address recoveredAddress = ecrecover(digest, v, r, s);

        // Explicitly disallow authorizations for address(0) as ecrecover returns address(0) on malformed messages

        require(

            recoveredAddress != address(0) && recoveredAddress == signer,

            "HEZ::_validateSignedData: INVALID_SIGNATURE"

        );

    }



    function getChainId() public pure returns (uint256 chainId){

        assembly { chainId := chainid() }

    }



    function _mint(address to, uint256 value) internal {

        totalSupply = totalSupply.add(value);

        balanceOf[to] = balanceOf[to].add(value);

        emit Transfer(address(0), to, value);

    }



    function _burn(address from, uint value) internal {

        // Balance is implicitly checked with SafeMath's underflow protection

        balanceOf[from] = balanceOf[from].sub(value);

        totalSupply = totalSupply.sub(value);

        emit Transfer(from, address(0), value);

    }



    function _approve(

        address owner,

        address spender,

        uint256 value

    ) private {

        allowance[owner][spender] = value;

        emit Approval(owner, spender, value);

    }



    function _transfer(

        address from,

        address to,

        uint256 value

    ) private {

        require(

            to != address(this) && to != address(0),

            "HEZ::_transfer: NOT_VALID_TRANSFER"

        );

        // Balance is implicitly checked with SafeMath's underflow protection

        balanceOf[from] = balanceOf[from].sub(value);

        balanceOf[to] = balanceOf[to].add(value);

        emit Transfer(from, to, value);

    }



    function burn(uint256 value) external returns (bool) {

        _burn(msg.sender, value);

        return true;

    }



    function approve(address spender, uint256 value)

        external

        override

        returns (bool)

    {

        _approve(msg.sender, spender, value);

        return true;

    }



    function transfer(address to, uint256 value)

        external

        override

        returns (bool)

    {

        _transfer(msg.sender, to, value);

        return true;

    }



    function transferFrom(

        address from,

        address to,

        uint256 value

    ) external override returns (bool) {

        uint256 fromAllowance = allowance[from][msg.sender];

        if (fromAllowance != uint256(-1)) {

            // Allowance is implicitly checked with SafeMath's underflow protection

            allowance[from][msg.sender] = fromAllowance.sub(value);

        }

        _transfer(from, to, value);

        return true;

    }



    function permit(

        address owner,

        address spender,

        uint256 value,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) external {

        require(deadline >= block.timestamp, "HEZ::permit: AUTH_EXPIRED");

        bytes32 encodeData = keccak256(

            abi.encode(

                PERMIT_TYPEHASH,

                owner,

                spender,

                value,

                nonces[owner]++,

                deadline

            )

        );

        _validateSignedData(owner, encodeData, v, r, s);

        _approve(owner, spender, value);

    }



    function transferWithAuthorization(

        address from,

        address to,

        uint256 value,

        uint256 validAfter,

        uint256 validBefore,

        bytes32 nonce,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) external {

        require(block.timestamp > validAfter, "HEZ::transferWithAuthorization: AUTH_NOT_YET_VALID");

        require(block.timestamp < validBefore, "HEZ::transferWithAuthorization: AUTH_EXPIRED");

        require(!authorizationState[from][nonce], "HEZ::transferWithAuthorization: AUTH_ALREADY_USED");



        bytes32 encodeData = keccak256(

            abi.encode(

                TRANSFER_WITH_AUTHORIZATION_TYPEHASH,

                from,

                to,

                value,

                validAfter,

                validBefore,

                nonce

            )

        );

        _validateSignedData(from, encodeData, v, r, s);



        authorizationState[from][nonce] = true;

        _transfer(from, to, value);

        emit AuthorizationUsed(from, nonce);

    }

}

contract HEZMock is HEZ {

    constructor(address initialHolder)

        public

        HEZ(initialHolder)

    {}



    function mint(address to, uint256 value) external {

        super._mint(to, value);

    }

}
