/**
 *Submitted for verification at Etherscan.io on 2021-11-26
*/

// SPDX-License-Identifier: MIT

pragma solidity 0.6.12;

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
     * @dev Returns the decimals places of the token.
     */
    function decimals() external view returns (uint8);

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

contract VictoriaVRVesting {
    using SafeMath for uint256;

    IERC20 public token;

    /**
     * Time Zone: UTC
     * Start Date: 2022-04-02 08:00:00 AM
     * Last Date: 2025-03-02 08:00:00 AM
     */ 
    uint[36] public LockedDateList = [
        1648886400, 1651478400, 1654156800, 1656748800, 1659427200, 1662105600,
        1664697600, 1667376000, 1669968000, 1672646400, 1675324800, 1677744000,
        1680422400, 1683014400, 1685692800, 1688284800, 1690963200, 1693641600,
        1696233600, 1698912000, 1701504000, 1704182400, 1706860800, 1709366400,
        1712044800, 1714636800, 1717315200, 1719907200, 1722585600, 1725264000,
        1727856000, 1730534400, 1733126400, 1735804800, 1738483200, 1740902400
    ];
    
    uint256 public totalLockedToken;
    uint256 public monthUnlockToken;
    address public unlockAddress = 0x5cb4d03b656Ca2F8F61A30142F455E92553AF292;

    uint256 public firstDate;
    uint256 public firstUnlockToken;
    bool public isFirstUnlockState;
    
    uint256 public currentUnlockToken;
    uint256 public lastUnlockTime;
    uint256 public maxUnlockingTimes = 36;

    event FirstUnlock(address indexed mananger, uint256 amount);
    
    event MonthUnlock(address indexed mananger, uint256 day, uint256 amount);

    modifier unlockCheck() {
        if(currentUnlockToken == 0) {
            require(
                balanceOf() >= totalLockedToken,
                "The project party is requested to transfer enough tokens to start the lock up contract"
            );
        }
        require(msg.sender == unlockAddress, "You do not have permission to unlock");
        _;
    }

    constructor(address _token) public {
        token = IERC20(_token);
        firstDate = 1638432000; //  UTC 2021-12-02 08:00:00 AM
        uint256 _decimals = token.decimals();
        totalLockedToken = (10 ** _decimals).mul(169_491_525_4237288).div(1000_0000); // total 169,491,525.4237288
        firstUnlockToken = totalLockedToken.mul(10).div(100); // 10%
        monthUnlockToken = totalLockedToken.sub(firstUnlockToken).mul(25).div(1000);  // 90% / 36 = 2.5%
    }

    function blockTimestamp() public view returns(uint256) {
        return block.timestamp;
    }

    function getUnlockedTimes() public view returns(uint256) {
        uint256 allTimes;
        for(uint i = 0; i < LockedDateList.length; i++) {
            if(blockTimestamp() >= LockedDateList[i]) {
                allTimes++;
            }
        }
        return allTimes;
    }

    function balanceOf() public view returns(uint256) {
        return token.balanceOf(address(this));
    }

    function managerBalanceOf() public view returns(uint256) {
        return token.balanceOf(unlockAddress);
    }

    function firstUnlock() public unlockCheck {
        require(blockTimestamp() >= firstDate, "It's not time to unlock for the first time");
        require(isFirstUnlockState == false, "The first unlocking has been performed, and cannot be repeated");
        currentUnlockToken = currentUnlockToken.add(firstUnlockToken);
        _safeTransfer(currentUnlockToken);
        isFirstUnlockState = true;
        emit FirstUnlock(unlockAddress, firstUnlockToken);
    }

    function monthUnlock() public unlockCheck {
        require(balanceOf() > 0, "There is no balance to unlock and withdraw");
        uint256 unlockTime = getUnlockedTimes();
        uint256 unlockToken;
        if(unlockTime >= maxUnlockingTimes) {
            unlockToken = balanceOf();
            lastUnlockTime = maxUnlockingTimes;
        } else {
            require(unlockTime > lastUnlockTime, "No current extractable times");
            unlockToken = unlockTime.sub(lastUnlockTime).mul(monthUnlockToken);
            lastUnlockTime = unlockTime;
        }
        currentUnlockToken = currentUnlockToken.add(unlockToken);
        _safeTransfer(unlockToken);
        emit MonthUnlock(unlockAddress, unlockTime, unlockToken);
    }
    
    function _safeTransfer(uint256 unlockToken) private {
        require(balanceOf() >= unlockToken, "Insufficient available balance for transfer");
        token.transfer(unlockAddress, unlockToken);
    }
}