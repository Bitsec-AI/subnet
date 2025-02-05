pragma solidity 0.6.7;
pragma experimental ABIEncoderV2;

contract ControllerV4 {

    using SafeERC20 for IERC20;

    using Address for address;

    using SafeMath for uint256;



    address public constant burn = 0x000000000000000000000000000000000000dEaD;

    address public onesplit = 0xC586BeF4a0992C495Cf22e1aeEE4E446CECDee0E;



    address public governance;

    address public strategist;

    address public devfund;

    address public treasury;

    address public timelock;



    // Convenience fee 0.1%

    uint256 public convenienceFee = 100;

    uint256 public constant convenienceFeeMax = 100000;



    mapping(address => address) public jars;

    mapping(address => address) public strategies;

    mapping(address => mapping(address => address)) public converters;

    mapping(address => mapping(address => bool)) public approvedStrategies;

    mapping(address => bool) public approvedJarConverters;



    uint256 public split = 500;

    uint256 public constant max = 10000;



    constructor(

        address _governance,

        address _strategist,

        address _timelock,

        address _devfund,

        address _treasury

    ) public {

        governance = _governance;

        strategist = _strategist;

        timelock = _timelock;

        devfund = _devfund;

        treasury = _treasury;

    }



    function setDevFund(address _devfund) public {

        require(msg.sender == governance, "!governance");

        devfund = _devfund;

    }



    function setTreasury(address _treasury) public {

        require(msg.sender == governance, "!governance");

        treasury = _treasury;

    }



    function setStrategist(address _strategist) public {

        require(msg.sender == governance, "!governance");

        strategist = _strategist;

    }



    function setSplit(uint256 _split) public {

        require(msg.sender == governance, "!governance");

        split = _split;

    }



    function setOneSplit(address _onesplit) public {

        require(msg.sender == governance, "!governance");

        onesplit = _onesplit;

    }



    function setGovernance(address _governance) public {

        require(msg.sender == governance, "!governance");

        governance = _governance;

    }



    function setTimelock(address _timelock) public {

        require(msg.sender == timelock, "!timelock");

        timelock = _timelock;

    }



    function setJar(address _token, address _jar) public {

        require(

            msg.sender == strategist || msg.sender == governance,

            "!strategist"

        );

        require(jars[_token] == address(0), "jar");

        jars[_token] = _jar;

    }



    function approveJarConverter(address _converter) public {

        require(msg.sender == governance, "!governance");

        approvedJarConverters[_converter] = true;

    }



    function revokeJarConverter(address _converter) public {

        require(msg.sender == governance, "!governance");

        approvedJarConverters[_converter] = false;

    }



    function approveStrategy(address _token, address _strategy) public {

        require(msg.sender == timelock, "!timelock");

        approvedStrategies[_token][_strategy] = true;

    }



    function revokeStrategy(address _token, address _strategy) public {

        require(msg.sender == governance, "!governance");

        approvedStrategies[_token][_strategy] = false;

    }



    function setConvenienceFee(uint256 _convenienceFee) external {

        require(msg.sender == timelock, "!timelock");

        convenienceFee = _convenienceFee;

    }



    function setStrategy(address _token, address _strategy) public {

        require(

            msg.sender == strategist || msg.sender == governance,

            "!strategist"

        );

        require(approvedStrategies[_token][_strategy] == true, "!approved");



        address _current = strategies[_token];

        if (_current != address(0)) {

            IStrategy(_current).withdrawAll();

        }

        strategies[_token] = _strategy;

    }



    function earn(address _token, uint256 _amount) public {

        address _strategy = strategies[_token];

        address _want = IStrategy(_strategy).want();

        if (_want != _token) {

            address converter = converters[_token][_want];

            IERC20(_token).safeTransfer(converter, _amount);

            _amount = Converter(converter).convert(_strategy);

            IERC20(_want).safeTransfer(_strategy, _amount);

        } else {

            IERC20(_token).safeTransfer(_strategy, _amount);

        }

        IStrategy(_strategy).deposit();

    }



    function balanceOf(address _token) external view returns (uint256) {

        return IStrategy(strategies[_token]).balanceOf();

    }



    function withdrawAll(address _token) public {

        require(

            msg.sender == strategist || msg.sender == governance,

            "!strategist"

        );

        IStrategy(strategies[_token]).withdrawAll();

    }



    function inCaseTokensGetStuck(address _token, uint256 _amount) public {

        require(

            msg.sender == strategist || msg.sender == governance,

            "!governance"

        );

        IERC20(_token).safeTransfer(msg.sender, _amount);

    }



    function inCaseStrategyTokenGetStuck(address _strategy, address _token)

        public

    {

        require(

            msg.sender == strategist || msg.sender == governance,

            "!governance"

        );

        IStrategy(_strategy).withdraw(_token);

    }



    function getExpectedReturn(

        address _strategy,

        address _token,

        uint256 parts

    ) public view returns (uint256 expected) {

        uint256 _balance = IERC20(_token).balanceOf(_strategy);

        address _want = IStrategy(_strategy).want();

        (expected, ) = OneSplitAudit(onesplit).getExpectedReturn(

            _token,

            _want,

            _balance,

            parts,

            0

        );

    }



    // Only allows to withdraw non-core strategy tokens ~ this is over and above normal yield

    function yearn(

        address _strategy,

        address _token,

        uint256 parts

    ) public {

        require(

            msg.sender == strategist || msg.sender == governance,

            "!governance"

        );

        // This contract should never have value in it, but just incase since this is a public call

        uint256 _before = IERC20(_token).balanceOf(address(this));

        IStrategy(_strategy).withdraw(_token);

        uint256 _after = IERC20(_token).balanceOf(address(this));

        if (_after > _before) {

            uint256 _amount = _after.sub(_before);

            address _want = IStrategy(_strategy).want();

            uint256[] memory _distribution;

            uint256 _expected;

            _before = IERC20(_want).balanceOf(address(this));

            IERC20(_token).safeApprove(onesplit, 0);

            IERC20(_token).safeApprove(onesplit, _amount);

            (_expected, _distribution) = OneSplitAudit(onesplit)

                .getExpectedReturn(_token, _want, _amount, parts, 0);

            OneSplitAudit(onesplit).swap(

                _token,

                _want,

                _amount,

                _expected,

                _distribution,

                0

            );

            _after = IERC20(_want).balanceOf(address(this));

            if (_after > _before) {

                _amount = _after.sub(_before);

                uint256 _treasury = _amount.mul(split).div(max);

                earn(_want, _amount.sub(_treasury));

                IERC20(_want).safeTransfer(treasury, _treasury);

            }

        }

    }



    function withdraw(address _token, uint256 _amount) public {

        require(msg.sender == jars[_token], "!jar");

        IStrategy(strategies[_token]).withdraw(_amount);

    }



    // Function to swap between jars

    function swapExactJarForJar(

        address _fromJar, // From which Jar

        address _toJar, // To which Jar

        uint256 _fromJarAmount, // How much jar tokens to swap

        uint256 _toJarMinAmount, // How much jar tokens you'd like at a minimum

        address payable[] calldata _targets,

        bytes[] calldata _data

    ) external returns (uint256) {

        require(_targets.length == _data.length, "!length");



        // Only return last response

        for (uint256 i = 0; i < _targets.length; i++) {

            require(_targets[i] != address(0), "!converter");

            require(approvedJarConverters[_targets[i]], "!converter");

        }



        address _fromJarToken = IJar(_fromJar).token();

        address _toJarToken = IJar(_toJar).token();



        // Get pTokens from msg.sender

        IERC20(_fromJar).safeTransferFrom(

            msg.sender,

            address(this),

            _fromJarAmount

        );



        // Calculate how much underlying

        // is the amount of pTokens worth

        uint256 _fromJarUnderlyingAmount = _fromJarAmount

            .mul(IJar(_fromJar).getRatio())

            .div(10**uint256(IJar(_fromJar).decimals()));



        // Call 'withdrawForSwap' on Jar's current strategy if Jar

        // doesn't have enough initial capital.

        // This has moves the funds from the strategy to the Jar's

        // 'earnable' amount. Enabling 'free' withdrawals

        uint256 _fromJarAvailUnderlying = IERC20(_fromJarToken).balanceOf(

            _fromJar

        );

        if (_fromJarAvailUnderlying < _fromJarUnderlyingAmount) {

            IStrategy(strategies[_fromJarToken]).withdrawForSwap(

                _fromJarUnderlyingAmount.sub(_fromJarAvailUnderlying)

            );

        }



        // Withdraw from Jar

        // Note: this is free since its still within the "earnable" amount

        //       as we transferred the access

        IERC20(_fromJar).safeApprove(_fromJar, 0);

        IERC20(_fromJar).safeApprove(_fromJar, _fromJarAmount);

        IJar(_fromJar).withdraw(_fromJarAmount);



        // Calculate fee

        uint256 _fromUnderlyingBalance = IERC20(_fromJarToken).balanceOf(

            address(this)

        );

        uint256 _convenienceFee = _fromUnderlyingBalance.mul(convenienceFee).div(

            convenienceFeeMax

        );



        if (_convenienceFee > 1) {

            IERC20(_fromJarToken).safeTransfer(devfund, _convenienceFee.div(2));

            IERC20(_fromJarToken).safeTransfer(treasury, _convenienceFee.div(2));

        }



        // Executes sequence of logic

        for (uint256 i = 0; i < _targets.length; i++) {

            _execute(_targets[i], _data[i]);

        }



        // Deposit into new Jar

        uint256 _toBal = IERC20(_toJarToken).balanceOf(address(this));

        IERC20(_toJarToken).safeApprove(_toJar, 0);

        IERC20(_toJarToken).safeApprove(_toJar, _toBal);

        IJar(_toJar).deposit(_toBal);



        // Send Jar Tokens to user

        uint256 _toJarBal = IJar(_toJar).balanceOf(address(this));

        if (_toJarBal < _toJarMinAmount) {

            revert("!min-jar-amount");

        }



        IJar(_toJar).transfer(msg.sender, _toJarBal);



        return _toJarBal;

    }



    function _execute(address _target, bytes memory _data)

        internal

        returns (bytes memory response)

    {

        require(_target != address(0), "!target");



        // call contract in current context

        assembly {

            let succeeded := delegatecall(

                sub(gas(), 5000),

                _target,

                add(_data, 0x20),

                mload(_data),

                0,

                0

            )

            let size := returndatasize()



            response := mload(0x40)

            mstore(

                0x40,

                add(response, and(add(add(size, 0x20), 0x1f), not(0x1f)))

            )

            mstore(response, size)

            returndatacopy(add(response, 0x20), 0, size)



            switch iszero(succeeded)

                case 1 {

                    // throw if delegatecall failed

                    revert(add(response, 0x20), size)

                }

        }

    }

}

contract Timelock {

    using SafeMath for uint;



    event NewAdmin(address indexed newAdmin);

    event NewPendingAdmin(address indexed newPendingAdmin);

    event NewDelay(uint indexed newDelay);

    event CancelTransaction(bytes32 indexed txHash, address indexed target, uint value, string signature,  bytes data, uint eta);

    event ExecuteTransaction(bytes32 indexed txHash, address indexed target, uint value, string signature,  bytes data, uint eta);

    event QueueTransaction(bytes32 indexed txHash, address indexed target, uint value, string signature, bytes data, uint eta);



    uint public constant GRACE_PERIOD = 14 days;

    uint public constant MINIMUM_DELAY = 2 days;

    uint public constant MAXIMUM_DELAY = 30 days;



    address public admin;

    address public pendingAdmin;

    uint public delay;

    bool public admin_initialized;



    mapping (bytes32 => bool) public queuedTransactions;





    constructor(address admin_, uint delay_) public {

        require(delay_ >= MINIMUM_DELAY, "Timelock::constructor: Delay must exceed minimum delay.");

        require(delay_ <= MAXIMUM_DELAY, "Timelock::constructor: Delay must not exceed maximum delay.");



        admin = admin_;

        delay = delay_;

        admin_initialized = false;

    }



    // XXX: function() external payable { }

    receive() external payable { }



    function setDelay(uint delay_) public {

        require(msg.sender == address(this), "Timelock::setDelay: Call must come from Timelock.");

        require(delay_ >= MINIMUM_DELAY, "Timelock::setDelay: Delay must exceed minimum delay.");

        require(delay_ <= MAXIMUM_DELAY, "Timelock::setDelay: Delay must not exceed maximum delay.");

        delay = delay_;



        emit NewDelay(delay);

    }



    function acceptAdmin() public {

        require(msg.sender == pendingAdmin, "Timelock::acceptAdmin: Call must come from pendingAdmin.");

        admin = msg.sender;

        pendingAdmin = address(0);



        emit NewAdmin(admin);

    }



    function setPendingAdmin(address pendingAdmin_) public {

        // allows one time setting of admin for deployment purposes

        if (admin_initialized) {

            require(msg.sender == address(this), "Timelock::setPendingAdmin: Call must come from Timelock.");

        } else {

            require(msg.sender == admin, "Timelock::setPendingAdmin: First call must come from admin.");

            admin_initialized = true;

        }

        pendingAdmin = pendingAdmin_;



        emit NewPendingAdmin(pendingAdmin);

    }



    function queueTransaction(address target, uint value, string memory signature, bytes memory data, uint eta) public returns (bytes32) {

        require(msg.sender == admin, "Timelock::queueTransaction: Call must come from admin.");

        require(eta >= getBlockTimestamp().add(delay), "Timelock::queueTransaction: Estimated execution block must satisfy delay.");



        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));

        queuedTransactions[txHash] = true;



        emit QueueTransaction(txHash, target, value, signature, data, eta);

        return txHash;

    }



    function cancelTransaction(address target, uint value, string memory signature, bytes memory data, uint eta) public {

        require(msg.sender == admin, "Timelock::cancelTransaction: Call must come from admin.");



        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));

        queuedTransactions[txHash] = false;



        emit CancelTransaction(txHash, target, value, signature, data, eta);

    }



    function executeTransaction(address target, uint value, string memory signature, bytes memory data, uint eta) public payable returns (bytes memory) {

        require(msg.sender == admin, "Timelock::executeTransaction: Call must come from admin.");



        bytes32 txHash = keccak256(abi.encode(target, value, signature, data, eta));

        require(queuedTransactions[txHash], "Timelock::executeTransaction: Transaction hasn't been queued.");

        require(getBlockTimestamp() >= eta, "Timelock::executeTransaction: Transaction hasn't surpassed time lock.");

        require(getBlockTimestamp() <= eta.add(GRACE_PERIOD), "Timelock::executeTransaction: Transaction is stale.");



        queuedTransactions[txHash] = false;



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



    function getBlockTimestamp() internal view returns (uint) {

        // solium-disable-next-line security/no-block-members

        return block.timestamp;

    }

}

interface ICToken {

    function totalSupply() external view returns (uint256);



    function totalBorrows() external returns (uint256);



    function borrowIndex() external returns (uint256);



    function repayBorrow(uint256 repayAmount) external returns (uint256);



    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);



    function borrow(uint256 borrowAmount) external returns (uint256);



    function mint(uint256 mintAmount) external returns (uint256);



    function transfer(address dst, uint256 amount) external returns (bool);



    function transferFrom(

        address src,

        address dst,

        uint256 amount

    ) external returns (bool);



    function approve(address spender, uint256 amount) external returns (bool);



    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



    function balanceOf(address owner) external view returns (uint256);



    function balanceOfUnderlying(address owner) external returns (uint256);



    function getAccountSnapshot(address account)

        external

        view

        returns (

            uint256,

            uint256,

            uint256,

            uint256

        );



    function borrowRatePerBlock() external view returns (uint256);



    function supplyRatePerBlock() external view returns (uint256);



    function totalBorrowsCurrent() external returns (uint256);



    function borrowBalanceCurrent(address account) external returns (uint256);



    function borrowBalanceStored(address account)

        external

        view

        returns (uint256);



    function exchangeRateCurrent() external returns (uint256);



    function exchangeRateStored() external view returns (uint256);



    function getCash() external view returns (uint256);



    function accrueInterest() external returns (uint256);



    function seize(

        address liquidator,

        address borrower,

        uint256 seizeTokens

    ) external returns (uint256);

}

interface ICEther {

    function mint() external payable;



    /**

     * @notice Sender redeems cTokens in exchange for the underlying asset

     * @dev Accrues interest whether or not the operation succeeds, unless reverted

     * @param redeemTokens The number of cTokens to redeem into underlying

     * @return uint 0=success, otherwise a failure (see ErrorReporter.sol for details)

     */

    function redeem(uint256 redeemTokens) external returns (uint256);



    /**

     * @notice Sender redeems cTokens in exchange for a specified amount of underlying asset

     * @dev Accrues interest whether or not the operation succeeds, unless reverted

     * @param redeemAmount The amount of underlying to redeem

     * @return uint 0=success, otherwise a failure (see ErrorReporter.sol for details)

     */

    function redeemUnderlying(uint256 redeemAmount) external returns (uint256);



    /**

     * @notice Sender borrows assets from the protocol to their own address

     * @param borrowAmount The amount of the underlying asset to borrow

     * @return uint 0=success, otherwise a failure (see ErrorReporter.sol for details)

     */

    function borrow(uint256 borrowAmount) external returns (uint256);



    /**

     * @notice Sender repays their own borrow

     * @dev Reverts upon any failure

     */

    function repayBorrow() external payable;



    /**

     * @notice Sender repays a borrow belonging to borrower

     * @dev Reverts upon any failure

     * @param borrower the account with the debt being payed off

     */

    function repayBorrowBehalf(address borrower) external payable;



    /**

     * @notice The sender liquidates the borrowers collateral.

     *  The collateral seized is transferred to the liquidator.

     * @dev Reverts upon any failure

     * @param borrower The borrower of this cToken to be liquidated

     * @param cTokenCollateral The market in which to seize collateral from the borrower

     */

    function liquidateBorrow(address borrower, address cTokenCollateral)

        external

        payable;

}

interface IComptroller {

    function compAccrued(address) external view returns (uint256);



    function compSupplierIndex(address, address)

        external

        view

        returns (uint256);



    function compBorrowerIndex(address, address)

        external

        view

        returns (uint256);



    function compSpeeds(address) external view returns (uint256);



    function compBorrowState(address) external view returns (uint224, uint32);



    function compSupplyState(address) external view returns (uint224, uint32);



    /*** Assets You Are In ***/



    function enterMarkets(address[] calldata cTokens)

        external

        returns (uint256[] memory);



    function exitMarket(address cToken) external returns (uint256);



    /*** Policy Hooks ***/



    function mintAllowed(

        address cToken,

        address minter,

        uint256 mintAmount

    ) external returns (uint256);



    function mintVerify(

        address cToken,

        address minter,

        uint256 mintAmount,

        uint256 mintTokens

    ) external;



    function redeemAllowed(

        address cToken,

        address redeemer,

        uint256 redeemTokens

    ) external returns (uint256);



    function redeemVerify(

        address cToken,

        address redeemer,

        uint256 redeemAmount,

        uint256 redeemTokens

    ) external;



    function borrowAllowed(

        address cToken,

        address borrower,

        uint256 borrowAmount

    ) external returns (uint256);



    function borrowVerify(

        address cToken,

        address borrower,

        uint256 borrowAmount

    ) external;



    function repayBorrowAllowed(

        address cToken,

        address payer,

        address borrower,

        uint256 repayAmount

    ) external returns (uint256);



    function repayBorrowVerify(

        address cToken,

        address payer,

        address borrower,

        uint256 repayAmount,

        uint256 borrowerIndex

    ) external;



    function liquidateBorrowAllowed(

        address cTokenBorrowed,

        address cTokenCollateral,

        address liquidator,

        address borrower,

        uint256 repayAmount

    ) external returns (uint256);



    function liquidateBorrowVerify(

        address cTokenBorrowed,

        address cTokenCollateral,

        address liquidator,

        address borrower,

        uint256 repayAmount,

        uint256 seizeTokens

    ) external;



    function seizeAllowed(

        address cTokenCollateral,

        address cTokenBorrowed,

        address liquidator,

        address borrower,

        uint256 seizeTokens

    ) external returns (uint256);



    function seizeVerify(

        address cTokenCollateral,

        address cTokenBorrowed,

        address liquidator,

        address borrower,

        uint256 seizeTokens

    ) external;



    function transferAllowed(

        address cToken,

        address src,

        address dst,

        uint256 transferTokens

    ) external returns (uint256);



    function transferVerify(

        address cToken,

        address src,

        address dst,

        uint256 transferTokens

    ) external;



    /*** Liquidity/Liquidation Calculations ***/



    function liquidateCalculateSeizeTokens(

        address cTokenBorrowed,

        address cTokenCollateral,

        uint256 repayAmount

    ) external view returns (uint256, uint256);



    // Claim all the COMP accrued by holder in all markets

    function claimComp(address holder) external;



    // Claim all the COMP accrued by holder in specific markets

    function claimComp(address holder, address[] calldata cTokens) external;



    // Claim all the COMP accrued by specific holders in specific markets for their supplies and/or borrows

    function claimComp(

        address[] calldata holders,

        address[] calldata cTokens,

        bool borrowers,

        bool suppliers

    ) external;



    function markets(address cTokenAddress)

        external

        view

        returns (bool, uint256);

}

interface ICompoundLens {

    function getCompBalanceMetadataExt(

        address comp,

        address comptroller,

        address account

    )

        external

        returns (

            uint256 balance,

            uint256 votes,

            address delegate,

            uint256 allocated

        );

}

interface IController {

    function jars(address) external view returns (address);



    function rewards() external view returns (address);



    function devfund() external view returns (address);



    function treasury() external view returns (address);



    function balanceOf(address) external view returns (uint256);



    function withdraw(address, uint256) external;



    function earn(address, uint256) external;

}

interface Converter {

    function convert(address) external returns (uint256);

}

interface ICurveFi_2 {

    function get_virtual_price() external view returns (uint256);



    function add_liquidity(uint256[2] calldata amounts, uint256 min_mint_amount)

        external;



    function remove_liquidity_imbalance(

        uint256[2] calldata amounts,

        uint256 max_burn_amount

    ) external;



    function remove_liquidity(uint256 _amount, uint256[2] calldata amounts)

        external;



    function exchange(

        int128 from,

        int128 to,

        uint256 _from_amount,

        uint256 _min_to_amount

    ) external;



    function balances(int128) external view returns (uint256);

}

interface ICurveFi_3 {

    function get_virtual_price() external view returns (uint256);



    function add_liquidity(uint256[3] calldata amounts, uint256 min_mint_amount)

        external;



    function remove_liquidity_imbalance(

        uint256[3] calldata amounts,

        uint256 max_burn_amount

    ) external;



    function remove_liquidity(uint256 _amount, uint256[3] calldata amounts)

        external;



    function exchange(

        int128 from,

        int128 to,

        uint256 _from_amount,

        uint256 _min_to_amount

    ) external;



    function balances(uint256) external view returns (uint256);

}

interface ICurveFi_4 {

    function get_virtual_price() external view returns (uint256);



    function add_liquidity(uint256[4] calldata amounts, uint256 min_mint_amount)

        external;



    function remove_liquidity_imbalance(

        uint256[4] calldata amounts,

        uint256 max_burn_amount

    ) external;



    function remove_liquidity(uint256 _amount, uint256[4] calldata amounts)

        external;



    function exchange(

        int128 from,

        int128 to,

        uint256 _from_amount,

        uint256 _min_to_amount

    ) external;



    function balances(int128) external view returns (uint256);

}

interface ICurveZap_4 {

    function add_liquidity(

        uint256[4] calldata uamounts,

        uint256 min_mint_amount

    ) external;



    function remove_liquidity(uint256 _amount, uint256[4] calldata min_uamounts)

        external;



    function remove_liquidity_imbalance(

        uint256[4] calldata uamounts,

        uint256 max_burn_amount

    ) external;



    function calc_withdraw_one_coin(uint256 _token_amount, int128 i)

        external

        returns (uint256);



    function remove_liquidity_one_coin(

        uint256 _token_amount,

        int128 i,

        uint256 min_uamount

    ) external;



    function remove_liquidity_one_coin(

        uint256 _token_amount,

        int128 i,

        uint256 min_uamount,

        bool donate_dust

    ) external;



    function withdraw_donated_dust() external;



    function coins(int128 arg0) external returns (address);



    function underlying_coins(int128 arg0) external returns (address);



    function curve() external returns (address);



    function token() external returns (address);

}

interface ICurveZap {

    function remove_liquidity_one_coin(

        uint256 _token_amount,

        int128 i,

        uint256 min_uamount

    ) external;

}

interface ICurveGauge {

    function deposit(uint256 _value) external;



    function deposit(uint256 _value, address addr) external;



    function balanceOf(address arg0) external view returns (uint256);



    function withdraw(uint256 _value) external;



    function withdraw(uint256 _value, bool claim_rewards) external;



    function claim_rewards() external;



    function claim_rewards(address addr) external;



    function claimable_tokens(address addr) external returns (uint256);



    function claimable_reward(address addr) external view returns (uint256);



    function integrate_fraction(address arg0) external view returns (uint256);

}

interface ICurveMintr {

    function mint(address) external;



    function minted(address arg0, address arg1) external view returns (uint256);

}

interface ICurveVotingEscrow {

    function locked(address arg0)

        external

        view

        returns (int128 amount, uint256 end);



    function locked__end(address _addr) external view returns (uint256);



    function create_lock(uint256, uint256) external;



    function increase_amount(uint256) external;



    function increase_unlock_time(uint256 _unlock_time) external;



    function withdraw() external;



    function smart_wallet_checker() external returns (address);

}

interface ICurveSmartContractChecker {

    function wallets(address) external returns (bool);



    function approveWallet(address _wallet) external;

}

interface IJarConverter {

    function convert(

        address _refundExcess, // address to send the excess amount when adding liquidity

        uint256 _amount, // UNI LP Amount

        bytes calldata _data

    ) external returns (uint256);

}

interface IMasterchef {

    function BONUS_MULTIPLIER() external view returns (uint256);



    function add(

        uint256 _allocPoint,

        address _lpToken,

        bool _withUpdate

    ) external;



    function bonusEndBlock() external view returns (uint256);



    function deposit(uint256 _pid, uint256 _amount) external;



    function dev(address _devaddr) external;



    function devFundDivRate() external view returns (uint256);



    function devaddr() external view returns (address);



    function emergencyWithdraw(uint256 _pid) external;



    function getMultiplier(uint256 _from, uint256 _to)

        external

        view

        returns (uint256);



    function massUpdatePools() external;



    function owner() external view returns (address);



    function pendingPickle(uint256 _pid, address _user)

        external

        view

        returns (uint256);



    function pickle() external view returns (address);



    function picklePerBlock() external view returns (uint256);



    function poolInfo(uint256)

        external

        view

        returns (

            address lpToken,

            uint256 allocPoint,

            uint256 lastRewardBlock,

            uint256 accPicklePerShare

        );



    function poolLength() external view returns (uint256);



    function renounceOwnership() external;



    function set(

        uint256 _pid,

        uint256 _allocPoint,

        bool _withUpdate

    ) external;



    function setBonusEndBlock(uint256 _bonusEndBlock) external;



    function setDevFundDivRate(uint256 _devFundDivRate) external;



    function setPicklePerBlock(uint256 _picklePerBlock) external;



    function startBlock() external view returns (uint256);



    function totalAllocPoint() external view returns (uint256);



    function transferOwnership(address newOwner) external;



    function updatePool(uint256 _pid) external;



    function userInfo(uint256, address)

        external

        view

        returns (uint256 amount, uint256 rewardDebt);



    function withdraw(uint256 _pid, uint256 _amount) external;

}

interface OneSplitAudit {

    function getExpectedReturn(

        address fromToken,

        address toToken,

        uint256 amount,

        uint256 parts,

        uint256 featureFlags

    )

        external

        view

        returns (uint256 returnAmount, uint256[] memory distribution);



    function swap(

        address fromToken,

        address toToken,

        uint256 amount,

        uint256 minReturn,

        uint256[] calldata distribution,

        uint256 featureFlags

    ) external payable;

}

interface Proxy {

    function execute(

        address to,

        uint256 value,

        bytes calldata data

    ) external returns (bool, bytes memory);



    function increaseAmount(uint256) external;

}

interface IStakingRewards {

    function balanceOf(address account) external view returns (uint256);



    function earned(address account) external view returns (uint256);



    function exit() external;



    function getReward() external;



    function getRewardForDuration() external view returns (uint256);



    function lastTimeRewardApplicable() external view returns (uint256);



    function lastUpdateTime() external view returns (uint256);



    function notifyRewardAmount(uint256 reward) external;



    function periodFinish() external view returns (uint256);



    function rewardPerToken() external view returns (uint256);



    function rewardPerTokenStored() external view returns (uint256);



    function rewardRate() external view returns (uint256);



    function rewards(address) external view returns (uint256);



    function rewardsDistribution() external view returns (address);



    function rewardsDuration() external view returns (uint256);



    function rewardsToken() external view returns (address);



    function stake(uint256 amount) external;



    function stakeWithPermit(

        uint256 amount,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) external;



    function stakingToken() external view returns (address);



    function totalSupply() external view returns (uint256);



    function userRewardPerTokenPaid(address) external view returns (uint256);



    function withdraw(uint256 amount) external;

}

interface IStakingRewardsFactory {

    function deploy(address stakingToken, uint256 rewardAmount) external;



    function isOwner() external view returns (bool);



    function notifyRewardAmount(address stakingToken) external;



    function notifyRewardAmounts() external;



    function owner() external view returns (address);



    function renounceOwnership() external;



    function rewardsToken() external view returns (address);



    function stakingRewardsGenesis() external view returns (uint256);



    function stakingRewardsInfoByStakingToken(address)

        external

        view

        returns (address stakingRewards, uint256 rewardAmount);



    function stakingTokens(uint256) external view returns (address);



    function transferOwnership(address newOwner) external;

}

interface IStrategy {

    function rewards() external view returns (address);



    function gauge() external view returns (address);



    function want() external view returns (address);



    function timelock() external view returns (address);



    function deposit() external;



    function withdrawForSwap(uint256) external returns (uint256);



    function withdraw(address) external;



    function withdraw(uint256) external;



    function skim() external;



    function withdrawAll() external returns (uint256);



    function balanceOf() external view returns (uint256);



    function harvest() external;



    function setTimelock(address) external;



    function setController(address _controller) external;



    function execute(address _target, bytes calldata _data)

        external

        payable

        returns (bytes memory response);



    function execute(bytes calldata _data)

        external

        payable

        returns (bytes memory response);

}

interface UniswapRouterV2 {

    function swapExactTokensForTokens(

        uint256 amountIn,

        uint256 amountOutMin,

        address[] calldata path,

        address to,

        uint256 deadline

    ) external returns (uint256[] memory amounts);



    function addLiquidity(

        address tokenA,

        address tokenB,

        uint256 amountADesired,

        uint256 amountBDesired,

        uint256 amountAMin,

        uint256 amountBMin,

        address to,

        uint256 deadline

    )

        external

        returns (

            uint256 amountA,

            uint256 amountB,

            uint256 liquidity

        );



    function addLiquidityETH(

        address token,

        uint256 amountTokenDesired,

        uint256 amountTokenMin,

        uint256 amountETHMin,

        address to,

        uint256 deadline

    )

        external

        payable

        returns (

            uint256 amountToken,

            uint256 amountETH,

            uint256 liquidity

        );



    function removeLiquidity(

        address tokenA,

        address tokenB,

        uint256 liquidity,

        uint256 amountAMin,

        uint256 amountBMin,

        address to,

        uint256 deadline

    ) external returns (uint256 amountA, uint256 amountB);



    function getAmountsOut(uint256 amountIn, address[] calldata path)

        external

        view

        returns (uint256[] memory amounts);



    function getAmountsIn(uint256 amountOut, address[] calldata path)

        external

        view

        returns (uint256[] memory amounts);



    function swapETHForExactTokens(

        uint256 amountOut,

        address[] calldata path,

        address to,

        uint256 deadline

    ) external payable returns (uint256[] memory amounts);



    function swapExactETHForTokens(

        uint256 amountOutMin,

        address[] calldata path,

        address to,

        uint256 deadline

    ) external payable returns (uint256[] memory amounts);

}

interface IUniswapV2Pair {

    event Approval(

        address indexed owner,

        address indexed spender,

        uint256 value

    );

    event Transfer(address indexed from, address indexed to, uint256 value);



    function name() external pure returns (string memory);



    function symbol() external pure returns (string memory);



    function decimals() external pure returns (uint8);



    function totalSupply() external view returns (uint256);



    function balanceOf(address owner) external view returns (uint256);



    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



    function approve(address spender, uint256 value) external returns (bool);



    function transfer(address to, uint256 value) external returns (bool);



    function transferFrom(

        address from,

        address to,

        uint256 value

    ) external returns (bool);



    function DOMAIN_SEPARATOR() external view returns (bytes32);



    function PERMIT_TYPEHASH() external pure returns (bytes32);



    function nonces(address owner) external view returns (uint256);



    function permit(

        address owner,

        address spender,

        uint256 value,

        uint256 deadline,

        uint8 v,

        bytes32 r,

        bytes32 s

    ) external;



    event Mint(address indexed sender, uint256 amount0, uint256 amount1);

    event Burn(

        address indexed sender,

        uint256 amount0,

        uint256 amount1,

        address indexed to

    );

    event Swap(

        address indexed sender,

        uint256 amount0In,

        uint256 amount1In,

        uint256 amount0Out,

        uint256 amount1Out,

        address indexed to

    );

    event Sync(uint112 reserve0, uint112 reserve1);



    function MINIMUM_LIQUIDITY() external pure returns (uint256);



    function factory() external view returns (address);



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



    function kLast() external view returns (uint256);



    function mint(address to) external returns (uint256 liquidity);



    function burn(address to)

        external

        returns (uint256 amount0, uint256 amount1);



    function swap(

        uint256 amount0Out,

        uint256 amount1Out,

        address to,

        bytes calldata data

    ) external;



    function skim(address to) external;



    function sync() external;

}

interface IUniswapV2Factory {

    event PairCreated(

        address indexed token0,

        address indexed token1,

        address pair,

        uint256

    );



    function getPair(address tokenA, address tokenB)

        external

        view

        returns (address pair);



    function allPairs(uint256) external view returns (address pair);



    function allPairsLength() external view returns (uint256);



    function feeTo() external view returns (address);



    function feeToSetter() external view returns (address);



    function createPair(address tokenA, address tokenB)

        external

        returns (address pair);

}

interface USDT {

    function approve(address guy, uint256 wad) external;



    function transfer(address _to, uint256 _value) external;

}

interface WETH {

    function name() external view returns (string memory);



    function approve(address guy, uint256 wad) external returns (bool);



    function totalSupply() external view returns (uint256);



    function transferFrom(

        address src,

        address dst,

        uint256 wad

    ) external returns (bool);



    function withdraw(uint256 wad) external;



    function decimals() external view returns (uint8);



    function balanceOf(address) external view returns (uint256);



    function symbol() external view returns (string memory);



    function transfer(address dst, uint256 wad) external returns (bool);



    function deposit() external payable;



    function allowance(address, address) external view returns (uint256);

}

contract CarefulMath {



    /**

     * @dev Possible error codes that we can return

     */

    enum MathError {

        NO_ERROR,

        DIVISION_BY_ZERO,

        INTEGER_OVERFLOW,

        INTEGER_UNDERFLOW

    }



    /**

    * @dev Multiplies two numbers, returns an error on overflow.

    */

    function mulUInt(uint a, uint b) internal pure returns (MathError, uint) {

        if (a == 0) {

            return (MathError.NO_ERROR, 0);

        }



        uint c = a * b;



        if (c / a != b) {

            return (MathError.INTEGER_OVERFLOW, 0);

        } else {

            return (MathError.NO_ERROR, c);

        }

    }



    /**

    * @dev Integer division of two numbers, truncating the quotient.

    */

    function divUInt(uint a, uint b) internal pure returns (MathError, uint) {

        if (b == 0) {

            return (MathError.DIVISION_BY_ZERO, 0);

        }



        return (MathError.NO_ERROR, a / b);

    }



    /**

    * @dev Subtracts two numbers, returns an error on overflow (i.e. if subtrahend is greater than minuend).

    */

    function subUInt(uint a, uint b) internal pure returns (MathError, uint) {

        if (b <= a) {

            return (MathError.NO_ERROR, a - b);

        } else {

            return (MathError.INTEGER_UNDERFLOW, 0);

        }

    }



    /**

    * @dev Adds two numbers, returns an error on overflow.

    */

    function addUInt(uint a, uint b) internal pure returns (MathError, uint) {

        uint c = a + b;



        if (c >= a) {

            return (MathError.NO_ERROR, c);

        } else {

            return (MathError.INTEGER_OVERFLOW, 0);

        }

    }



    /**

    * @dev add a and b and then subtract c

    */

    function addThenSubUInt(uint a, uint b, uint c) internal pure returns (MathError, uint) {

        (MathError err0, uint sum) = addUInt(a, b);



        if (err0 != MathError.NO_ERROR) {

            return (err0, 0);

        }



        return subUInt(sum, c);

    }

}

abstract contract Context {

    function _msgSender() internal view virtual returns (address payable) {

        return msg.sender;

    }



    function _msgData() internal view virtual returns (bytes memory) {

        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691

        return msg.data;

    }

}

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

contract ERC20 is Context, IERC20 {

    using SafeMath for uint256;

    using Address for address;



    mapping (address => uint256) private _balances;



    mapping (address => mapping (address => uint256)) private _allowances;



    uint256 private _totalSupply;



    string private _name;

    string private _symbol;

    uint8 private _decimals;



    /**

     * @dev Sets the values for {name} and {symbol}, initializes {decimals} with

     * a default value of 18.

     *

     * To select a different value for {decimals}, use {_setupDecimals}.

     *

     * All three of these values are immutable: they can only be set once during

     * construction.

     */

    constructor (string memory name, string memory symbol) public {

        _name = name;

        _symbol = symbol;

        _decimals = 18;

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

     * Ether and Wei. This is the value {ERC20} uses, unless {_setupDecimals} is

     * called.

     *

     * NOTE: This information is only used for _display_ purposes: it in

     * no way affects any of the arithmetic of the contract, including

     * {IERC20-balanceOf} and {IERC20-transfer}.

     */

    function decimals() public view returns (uint8) {

        return _decimals;

    }



    /**

     * @dev See {IERC20-totalSupply}.

     */

    function totalSupply() public view override returns (uint256) {

        return _totalSupply;

    }



    /**

     * @dev See {IERC20-balanceOf}.

     */

    function balanceOf(address account) public view override returns (uint256) {

        return _balances[account];

    }



    /**

     * @dev See {IERC20-transfer}.

     *

     * Requirements:

     *

     * - `recipient` cannot be the zero address.

     * - the caller must have a balance of at least `amount`.

     */

    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {

        _transfer(_msgSender(), recipient, amount);

        return true;

    }



    /**

     * @dev See {IERC20-allowance}.

     */

    function allowance(address owner, address spender) public view virtual override returns (uint256) {

        return _allowances[owner][spender];

    }



    /**

     * @dev See {IERC20-approve}.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function approve(address spender, uint256 amount) public virtual override returns (bool) {

        _approve(_msgSender(), spender, amount);

        return true;

    }



    /**

     * @dev See {IERC20-transferFrom}.

     *

     * Emits an {Approval} event indicating the updated allowance. This is not

     * required by the EIP. See the note at the beginning of {ERC20};

     *

     * Requirements:

     * - `sender` and `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     * - the caller must have allowance for ``sender``'s tokens of at least

     * `amount`.

     */

    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {

        _transfer(sender, recipient, amount);

        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));

        return true;

    }



    /**

     * @dev Atomically increases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     */

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {

        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));

        return true;

    }



    /**

     * @dev Atomically decreases the allowance granted to `spender` by the caller.

     *

     * This is an alternative to {approve} that can be used as a mitigation for

     * problems described in {IERC20-approve}.

     *

     * Emits an {Approval} event indicating the updated allowance.

     *

     * Requirements:

     *

     * - `spender` cannot be the zero address.

     * - `spender` must have allowance for the caller of at least

     * `subtractedValue`.

     */

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {

        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));

        return true;

    }



    /**

     * @dev Moves tokens `amount` from `sender` to `recipient`.

     *

     * This is internal function is equivalent to {transfer}, and can be used to

     * e.g. implement automatic token fees, slashing mechanisms, etc.

     *

     * Emits a {Transfer} event.

     *

     * Requirements:

     *

     * - `sender` cannot be the zero address.

     * - `recipient` cannot be the zero address.

     * - `sender` must have a balance of at least `amount`.

     */

    function _transfer(address sender, address recipient, uint256 amount) internal virtual {

        require(sender != address(0), "ERC20: transfer from the zero address");

        require(recipient != address(0), "ERC20: transfer to the zero address");



        _beforeTokenTransfer(sender, recipient, amount);



        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");

        _balances[recipient] = _balances[recipient].add(amount);

        emit Transfer(sender, recipient, amount);

    }



    /** @dev Creates `amount` tokens and assigns them to `account`, increasing

     * the total supply.

     *

     * Emits a {Transfer} event with `from` set to the zero address.

     *

     * Requirements

     *

     * - `to` cannot be the zero address.

     */

    function _mint(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: mint to the zero address");



        _beforeTokenTransfer(address(0), account, amount);



        _totalSupply = _totalSupply.add(amount);

        _balances[account] = _balances[account].add(amount);

        emit Transfer(address(0), account, amount);

    }



    /**

     * @dev Destroys `amount` tokens from `account`, reducing the

     * total supply.

     *

     * Emits a {Transfer} event with `to` set to the zero address.

     *

     * Requirements

     *

     * - `account` cannot be the zero address.

     * - `account` must have at least `amount` tokens.

     */

    function _burn(address account, uint256 amount) internal virtual {

        require(account != address(0), "ERC20: burn from the zero address");



        _beforeTokenTransfer(account, address(0), amount);



        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");

        _totalSupply = _totalSupply.sub(amount);

        emit Transfer(account, address(0), amount);

    }



    /**

     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.

     *

     * This internal function is equivalent to `approve`, and can be used to

     * e.g. set automatic allowances for certain subsystems, etc.

     *

     * Emits an {Approval} event.

     *

     * Requirements:

     *

     * - `owner` cannot be the zero address.

     * - `spender` cannot be the zero address.

     */

    function _approve(address owner, address spender, uint256 amount) internal virtual {

        require(owner != address(0), "ERC20: approve from the zero address");

        require(spender != address(0), "ERC20: approve to the zero address");



        _allowances[owner][spender] = amount;

        emit Approval(owner, spender, amount);

    }



    /**

     * @dev Sets {decimals} to a value other than the default one of 18.

     *

     * WARNING: This function should only be called from the constructor. Most

     * applications that interact with token contracts will not expect

     * {decimals} to ever change, and may work incorrectly if it does.

     */

    function _setupDecimals(uint8 decimals_) internal {

        _decimals = decimals_;

    }



    /**

     * @dev Hook that is called before any transfer of tokens. This includes

     * minting and burning.

     *

     * Calling conditions:

     *

     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens

     * will be to transferred to `to`.

     * - when `from` is zero, `amount` tokens will be minted for `to`.

     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.

     * - `from` and `to` are never both zero.

     *

     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].

     */

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }

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

contract Exponential is CarefulMath {

    uint constant expScale = 1e18;

    uint constant doubleScale = 1e36;

    uint constant halfExpScale = expScale/2;

    uint constant mantissaOne = expScale;



    struct Exp {

        uint mantissa;

    }



    struct Double {

        uint mantissa;

    }



    /**

     * @dev Creates an exponential from numerator and denominator values.

     *      Note: Returns an error if (`num` * 10e18) > MAX_INT,

     *            or if `denom` is zero.

     */

    function getExp(uint num, uint denom) pure internal returns (MathError, Exp memory) {

        (MathError err0, uint scaledNumerator) = mulUInt(num, expScale);

        if (err0 != MathError.NO_ERROR) {

            return (err0, Exp({mantissa: 0}));

        }



        (MathError err1, uint rational) = divUInt(scaledNumerator, denom);

        if (err1 != MathError.NO_ERROR) {

            return (err1, Exp({mantissa: 0}));

        }



        return (MathError.NO_ERROR, Exp({mantissa: rational}));

    }



    /**

     * @dev Adds two exponentials, returning a new exponential.

     */

    function addExp(Exp memory a, Exp memory b) pure internal returns (MathError, Exp memory) {

        (MathError error, uint result) = addUInt(a.mantissa, b.mantissa);



        return (error, Exp({mantissa: result}));

    }



    /**

     * @dev Subtracts two exponentials, returning a new exponential.

     */

    function subExp(Exp memory a, Exp memory b) pure internal returns (MathError, Exp memory) {

        (MathError error, uint result) = subUInt(a.mantissa, b.mantissa);



        return (error, Exp({mantissa: result}));

    }



    /**

     * @dev Multiply an Exp by a scalar, returning a new Exp.

     */

    function mulScalar(Exp memory a, uint scalar) pure internal returns (MathError, Exp memory) {

        (MathError err0, uint scaledMantissa) = mulUInt(a.mantissa, scalar);

        if (err0 != MathError.NO_ERROR) {

            return (err0, Exp({mantissa: 0}));

        }



        return (MathError.NO_ERROR, Exp({mantissa: scaledMantissa}));

    }



    /**

     * @dev Multiply an Exp by a scalar, then truncate to return an unsigned integer.

     */

    function mulScalarTruncate(Exp memory a, uint scalar) pure internal returns (MathError, uint) {

        (MathError err, Exp memory product) = mulScalar(a, scalar);

        if (err != MathError.NO_ERROR) {

            return (err, 0);

        }



        return (MathError.NO_ERROR, truncate(product));

    }



    /**

     * @dev Multiply an Exp by a scalar, truncate, then add an to an unsigned integer, returning an unsigned integer.

     */

    function mulScalarTruncateAddUInt(Exp memory a, uint scalar, uint addend) pure internal returns (MathError, uint) {

        (MathError err, Exp memory product) = mulScalar(a, scalar);

        if (err != MathError.NO_ERROR) {

            return (err, 0);

        }



        return addUInt(truncate(product), addend);

    }



    /**

     * @dev Divide an Exp by a scalar, returning a new Exp.

     */

    function divScalar(Exp memory a, uint scalar) pure internal returns (MathError, Exp memory) {

        (MathError err0, uint descaledMantissa) = divUInt(a.mantissa, scalar);

        if (err0 != MathError.NO_ERROR) {

            return (err0, Exp({mantissa: 0}));

        }



        return (MathError.NO_ERROR, Exp({mantissa: descaledMantissa}));

    }



    /**

     * @dev Divide a scalar by an Exp, returning a new Exp.

     */

    function divScalarByExp(uint scalar, Exp memory divisor) pure internal returns (MathError, Exp memory) {

        /*

          We are doing this as:

          getExp(mulUInt(expScale, scalar), divisor.mantissa)

          How it works:

          Exp = a / b;

          Scalar = s;

          `s / (a / b)` = `b * s / a` and since for an Exp `a = mantissa, b = expScale`

        */

        (MathError err0, uint numerator) = mulUInt(expScale, scalar);

        if (err0 != MathError.NO_ERROR) {

            return (err0, Exp({mantissa: 0}));

        }

        return getExp(numerator, divisor.mantissa);

    }



    /**

     * @dev Divide a scalar by an Exp, then truncate to return an unsigned integer.

     */

    function divScalarByExpTruncate(uint scalar, Exp memory divisor) pure internal returns (MathError, uint) {

        (MathError err, Exp memory fraction) = divScalarByExp(scalar, divisor);

        if (err != MathError.NO_ERROR) {

            return (err, 0);

        }



        return (MathError.NO_ERROR, truncate(fraction));

    }



    /**

     * @dev Multiplies two exponentials, returning a new exponential.

     */

    function mulExp(Exp memory a, Exp memory b) pure internal returns (MathError, Exp memory) {



        (MathError err0, uint doubleScaledProduct) = mulUInt(a.mantissa, b.mantissa);

        if (err0 != MathError.NO_ERROR) {

            return (err0, Exp({mantissa: 0}));

        }



        // We add half the scale before dividing so that we get rounding instead of truncation.

        //  See "Listing 6" and text above it at https://accu.org/index.php/journals/1717

        // Without this change, a result like 6.6...e-19 will be truncated to 0 instead of being rounded to 1e-18.

        (MathError err1, uint doubleScaledProductWithHalfScale) = addUInt(halfExpScale, doubleScaledProduct);

        if (err1 != MathError.NO_ERROR) {

            return (err1, Exp({mantissa: 0}));

        }



        (MathError err2, uint product) = divUInt(doubleScaledProductWithHalfScale, expScale);

        // The only error `div` can return is MathError.DIVISION_BY_ZERO but we control `expScale` and it is not zero.

        assert(err2 == MathError.NO_ERROR);



        return (MathError.NO_ERROR, Exp({mantissa: product}));

    }



    /**

     * @dev Multiplies two exponentials given their mantissas, returning a new exponential.

     */

    function mulExp(uint a, uint b) pure internal returns (MathError, Exp memory) {

        return mulExp(Exp({mantissa: a}), Exp({mantissa: b}));

    }



    /**

     * @dev Multiplies three exponentials, returning a new exponential.

     */

    function mulExp3(Exp memory a, Exp memory b, Exp memory c) pure internal returns (MathError, Exp memory) {

        (MathError err, Exp memory ab) = mulExp(a, b);

        if (err != MathError.NO_ERROR) {

            return (err, ab);

        }

        return mulExp(ab, c);

    }



    /**

     * @dev Divides two exponentials, returning a new exponential.

     *     (a/scale) / (b/scale) = (a/scale) * (scale/b) = a/b,

     *  which we can scale as an Exp by calling getExp(a.mantissa, b.mantissa)

     */

    function divExp(Exp memory a, Exp memory b) pure internal returns (MathError, Exp memory) {

        return getExp(a.mantissa, b.mantissa);

    }



    /**

     * @dev Truncates the given exp to a whole number value.

     *      For example, truncate(Exp{mantissa: 15 * expScale}) = 15

     */

    function truncate(Exp memory exp) pure internal returns (uint) {

        // Note: We are not using careful math here as we're performing a division that cannot fail

        return exp.mantissa / expScale;

    }



    /**

     * @dev Checks if first Exp is less than second Exp.

     */

    function lessThanExp(Exp memory left, Exp memory right) pure internal returns (bool) {

        return left.mantissa < right.mantissa;

    }



    /**

     * @dev Checks if left Exp <= right Exp.

     */

    function lessThanOrEqualExp(Exp memory left, Exp memory right) pure internal returns (bool) {

        return left.mantissa <= right.mantissa;

    }



    /**

     * @dev Checks if left Exp > right Exp.

     */

    function greaterThanExp(Exp memory left, Exp memory right) pure internal returns (bool) {

        return left.mantissa > right.mantissa;

    }



    /**

     * @dev returns true if Exp is exactly zero

     */

    function isZeroExp(Exp memory value) pure internal returns (bool) {

        return value.mantissa == 0;

    }



    function safe224(uint n, string memory errorMessage) pure internal returns (uint224) {

        require(n < 2**224, errorMessage);

        return uint224(n);

    }



    function safe32(uint n, string memory errorMessage) pure internal returns (uint32) {

        require(n < 2**32, errorMessage);

        return uint32(n);

    }



    function add_(Exp memory a, Exp memory b) pure internal returns (Exp memory) {

        return Exp({mantissa: add_(a.mantissa, b.mantissa)});

    }



    function add_(Double memory a, Double memory b) pure internal returns (Double memory) {

        return Double({mantissa: add_(a.mantissa, b.mantissa)});

    }



    function add_(uint a, uint b) pure internal returns (uint) {

        return add_(a, b, "addition overflow");

    }



    function add_(uint a, uint b, string memory errorMessage) pure internal returns (uint) {

        uint c = a + b;

        require(c >= a, errorMessage);

        return c;

    }



    function sub_(Exp memory a, Exp memory b) pure internal returns (Exp memory) {

        return Exp({mantissa: sub_(a.mantissa, b.mantissa)});

    }



    function sub_(Double memory a, Double memory b) pure internal returns (Double memory) {

        return Double({mantissa: sub_(a.mantissa, b.mantissa)});

    }



    function sub_(uint a, uint b) pure internal returns (uint) {

        return sub_(a, b, "subtraction underflow");

    }



    function sub_(uint a, uint b, string memory errorMessage) pure internal returns (uint) {

        require(b <= a, errorMessage);

        return a - b;

    }



    function mul_(Exp memory a, Exp memory b) pure internal returns (Exp memory) {

        return Exp({mantissa: mul_(a.mantissa, b.mantissa) / expScale});

    }



    function mul_(Exp memory a, uint b) pure internal returns (Exp memory) {

        return Exp({mantissa: mul_(a.mantissa, b)});

    }



    function mul_(uint a, Exp memory b) pure internal returns (uint) {

        return mul_(a, b.mantissa) / expScale;

    }



    function mul_(Double memory a, Double memory b) pure internal returns (Double memory) {

        return Double({mantissa: mul_(a.mantissa, b.mantissa) / doubleScale});

    }



    function mul_(Double memory a, uint b) pure internal returns (Double memory) {

        return Double({mantissa: mul_(a.mantissa, b)});

    }



    function mul_(uint a, Double memory b) pure internal returns (uint) {

        return mul_(a, b.mantissa) / doubleScale;

    }



    function mul_(uint a, uint b) pure internal returns (uint) {

        return mul_(a, b, "multiplication overflow");

    }



    function mul_(uint a, uint b, string memory errorMessage) pure internal returns (uint) {

        if (a == 0 || b == 0) {

            return 0;

        }

        uint c = a * b;

        require(c / a == b, errorMessage);

        return c;

    }



    function div_(Exp memory a, Exp memory b) pure internal returns (Exp memory) {

        return Exp({mantissa: div_(mul_(a.mantissa, expScale), b.mantissa)});

    }



    function div_(Exp memory a, uint b) pure internal returns (Exp memory) {

        return Exp({mantissa: div_(a.mantissa, b)});

    }



    function div_(uint a, Exp memory b) pure internal returns (uint) {

        return div_(mul_(a, expScale), b.mantissa);

    }



    function div_(Double memory a, Double memory b) pure internal returns (Double memory) {

        return Double({mantissa: div_(mul_(a.mantissa, doubleScale), b.mantissa)});

    }



    function div_(Double memory a, uint b) pure internal returns (Double memory) {

        return Double({mantissa: div_(a.mantissa, b)});

    }



    function div_(uint a, Double memory b) pure internal returns (uint) {

        return div_(mul_(a, doubleScale), b.mantissa);

    }



    function div_(uint a, uint b) pure internal returns (uint) {

        return div_(a, b, "divide by zero");

    }



    function div_(uint a, uint b, string memory errorMessage) pure internal returns (uint) {

        require(b > 0, errorMessage);

        return a / b;

    }



    function fraction(uint a, uint b) pure internal returns (Double memory) {

        return Double({mantissa: div_(mul_(a, doubleScale), b)});

    }

}

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

contract Owned {

    address public owner;

    address public nominatedOwner;



    constructor(address _owner) public {

        require(_owner != address(0), "Owner address cannot be 0");

        owner = _owner;

        emit OwnerChanged(address(0), _owner);

    }



    function nominateNewOwner(address _owner) external onlyOwner {

        nominatedOwner = _owner;

        emit OwnerNominated(_owner);

    }



    function acceptOwnership() external {

        require(

            msg.sender == nominatedOwner,

            "You must be nominated before you can accept ownership"

        );

        emit OwnerChanged(owner, nominatedOwner);

        owner = nominatedOwner;

        nominatedOwner = address(0);

    }



    modifier onlyOwner {

        _onlyOwner();

        _;

    }



    function _onlyOwner() private view {

        require(

            msg.sender == owner,

            "Only the contract owner may perform this action"

        );

    }



    event OwnerNominated(address newOwner);

    event OwnerChanged(address oldOwner, address newOwner);

}

abstract contract Pausable is Owned {

    uint256 public lastPauseTime;

    bool public paused;



    constructor() internal {

        // This contract is abstract, and thus cannot be instantiated directly

        require(owner != address(0), "Owner must be set");

        // Paused will be false, and lastPauseTime will be 0 upon initialisation

    }



    /**

     * @notice Change the paused state of the contract

     * @dev Only the contract owner may call this.

     */

    function setPaused(bool _paused) external onlyOwner {

        // Ensure we're actually changing the state before we do anything

        if (_paused == paused) {

            return;

        }



        // Set our paused state.

        paused = _paused;



        // If applicable, set the last pause time.

        if (paused) {

            lastPauseTime = now;

        }



        // Let everyone know that our pause state has changed.

        emit PauseChanged(paused);

    }



    event PauseChanged(bool isPaused);



    modifier notPaused {

        require(

            !paused,

            "This action cannot be performed while the contract is paused"

        );

        _;

    }

}

contract ReentrancyGuard {

    // Booleans are more expensive than uint256 or any type that takes up a full

    // word because each write operation emits an extra SLOAD to first read the

    // slot's contents, replace the bits taken up by the boolean, and then write

    // back. This is the compiler's defense against contract upgrades and

    // pointer aliasing, and it cannot be disabled.



    // The values being non-zero value makes deployment a bit more expensive,

    // but in exchange the refund on every call to nonReentrant will be lower in

    // amount. Since refunds are capped to a percentage of the total

    // transaction's gas, it is best to keep them low in cases like this one, to

    // increase the likelihood of the full refund coming into effect.

    uint256 private constant _NOT_ENTERED = 1;

    uint256 private constant _ENTERED = 2;



    uint256 private _status;



    constructor () internal {

        _status = _NOT_ENTERED;

    }



    /**

     * @dev Prevents a contract from calling itself, directly or indirectly.

     * Calling a `nonReentrant` function from another `nonReentrant`

     * function is not supported. It is possible to prevent this from happening

     * by making the `nonReentrant` function external, and make it call a

     * `private` function that does the actual work.

     */

    modifier nonReentrant() {

        // On the first call to nonReentrant, _notEntered will be true

        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");



        // Any calls to nonReentrant after this point will fail

        _status = _ENTERED;



        _;



        // By storing the original value once again, a refund is triggered (see

        // https://eips.ethereum.org/EIPS/eip-2200)

        _status = _NOT_ENTERED;

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

contract PickleJar is ERC20 {

    using SafeERC20 for IERC20;

    using Address for address;

    using SafeMath for uint256;



    IERC20 public token;



    uint256 public min = 9500;

    uint256 public constant max = 10000;



    address public governance;

    address public timelock;

    address public controller;



    constructor(address _token, address _governance, address _timelock, address _controller)

        public

        ERC20(

            string(abi.encodePacked("pickling ", ERC20(_token).name())),

            string(abi.encodePacked("p", ERC20(_token).symbol()))

        )

    {

        _setupDecimals(ERC20(_token).decimals());

        token = IERC20(_token);

        governance = _governance;

        timelock = _timelock;

        controller = _controller;

    }



    function balance() public view returns (uint256) {

        return

            token.balanceOf(address(this)).add(

                IController(controller).balanceOf(address(token))

            );

    }



    function setMin(uint256 _min) external {

        require(msg.sender == governance, "!governance");

        min = _min;

    }



    function setGovernance(address _governance) public {

        require(msg.sender == governance, "!governance");

        governance = _governance;

    }



    function setTimelock(address _timelock) public {

        require(msg.sender == timelock, "!timelock");

        timelock = _timelock;

    }



    function setController(address _controller) public {

        require(msg.sender == timelock, "!timelock");

        controller = _controller;

    }



    // Custom logic in here for how much the jars allows to be borrowed

    // Sets minimum required on-hand to keep small withdrawals cheap

    function available() public view returns (uint256) {

        return token.balanceOf(address(this)).mul(min).div(max);

    }



    function earn() public {

        uint256 _bal = available();

        token.safeTransfer(controller, _bal);

        IController(controller).earn(address(token), _bal);

    }



    function depositAll() external {

        deposit(token.balanceOf(msg.sender));

    }



    function deposit(uint256 _amount) public {

        uint256 _pool = balance();

        uint256 _before = token.balanceOf(address(this));

        token.safeTransferFrom(msg.sender, address(this), _amount);

        uint256 _after = token.balanceOf(address(this));

        _amount = _after.sub(_before); // Additional check for deflationary tokens

        uint256 shares = 0;

        if (totalSupply() == 0) {

            shares = _amount;

        } else {

            shares = (_amount.mul(totalSupply())).div(_pool);

        }

        _mint(msg.sender, shares);

    }



    function withdrawAll() external {

        withdraw(balanceOf(msg.sender));

    }



    // Used to swap any borrowed reserve over the debt limit to liquidate to 'token'

    function harvest(address reserve, uint256 amount) external {

        require(msg.sender == controller, "!controller");

        require(reserve != address(token), "token");

        IERC20(reserve).safeTransfer(controller, amount);

    }



    // No rebalance implementation for lower fees and faster swaps

    function withdraw(uint256 _shares) public {

        uint256 r = (balance().mul(_shares)).div(totalSupply());

        _burn(msg.sender, _shares);



        // Check balance

        uint256 b = token.balanceOf(address(this));

        if (b < r) {

            uint256 _withdraw = r.sub(b);

            IController(controller).withdraw(address(token), _withdraw);

            uint256 _after = token.balanceOf(address(this));

            uint256 _diff = _after.sub(b);

            if (_diff < _withdraw) {

                r = b.add(_diff);

            }

        }



        token.safeTransfer(msg.sender, r);

    }



    function getRatio() public view returns (uint256) {

        return balance().mul(1e18).div(totalSupply());

    }

}

contract PickleSwap {

    using SafeERC20 for IERC20;



    UniswapRouterV2 router = UniswapRouterV2(

        0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D

    );



    address public constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;



    function convertWETHPair(

        address fromLP,

        address toLP,

        uint256 value

    ) public {

        IUniswapV2Pair fromPair = IUniswapV2Pair(fromLP);

        IUniswapV2Pair toPair = IUniswapV2Pair(toLP);



        // Only for WETH/<TOKEN> pairs

        if (!(fromPair.token0() == weth || fromPair.token1() == weth)) {

            revert("!eth-from");

        }

        if (!(toPair.token0() == weth || toPair.token1() == weth)) {

            revert("!eth-to");

        }



        // Get non-eth token from pairs

        address _from = fromPair.token0() != weth

            ? fromPair.token0()

            : fromPair.token1();



        address _to = toPair.token0() != weth

            ? toPair.token0()

            : toPair.token1();



        // Transfer

        IERC20(fromLP).safeTransferFrom(msg.sender, address(this), value);



        // Remove liquidity

        IERC20(fromLP).safeApprove(address(router), 0);

        IERC20(fromLP).safeApprove(address(router), value);

        router.removeLiquidity(

            fromPair.token0(),

            fromPair.token1(),

            value,

            0,

            0,

            address(this),

            now + 60

        );



        // Convert to target token

        address[] memory path = new address[](3);

        path[0] = _from;

        path[1] = weth;

        path[2] = _to;



        IERC20(_from).safeApprove(address(router), 0);

        IERC20(_from).safeApprove(address(router), uint256(-1));

        router.swapExactTokensForTokens(

            IERC20(_from).balanceOf(address(this)),

            0,

            path,

            address(this),

            now + 60

        );



        // Supply liquidity

        IERC20(weth).safeApprove(address(router), 0);

        IERC20(weth).safeApprove(address(router), uint256(-1));



        IERC20(_to).safeApprove(address(router), 0);

        IERC20(_to).safeApprove(address(router), uint256(-1));

        router.addLiquidity(

            weth,

            _to,

            IERC20(weth).balanceOf(address(this)),

            IERC20(_to).balanceOf(address(this)),

            0,

            0,

            msg.sender,

            now + 60

        );



        // Refund sender any remaining tokens

        IERC20(weth).safeTransfer(

            msg.sender,

            IERC20(weth).balanceOf(address(this))

        );

        IERC20(_to).safeTransfer(msg.sender, IERC20(_to).balanceOf(address(this)));

    }

}

contract CurveProxyLogic {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    function remove_liquidity_one_coin(

        address curve,

        address curveLp,

        int128 index

    ) public {

        uint256 lpAmount = IERC20(curveLp).balanceOf(address(this));



        IERC20(curveLp).safeApprove(curve, 0);

        IERC20(curveLp).safeApprove(curve, lpAmount);



        ICurveZap(curve).remove_liquidity_one_coin(lpAmount, index, 0);

    }



    function add_liquidity(

        address curve,

        bytes4 curveFunctionSig,

        uint256 curvePoolSize,

        uint256 curveUnderlyingIndex,

        address underlying

    ) public {

        uint256 underlyingAmount = IERC20(underlying).balanceOf(address(this));



        // curveFunctionSig should be the abi.encodedFormat of

        // add_liquidity(uint256[N_COINS],uint256)

        // The reason why its here is because different curve pools

        // have a different function signature



        uint256[] memory liquidity = new uint256[](curvePoolSize);

        liquidity[curveUnderlyingIndex] = underlyingAmount;



        bytes memory callData = abi.encodePacked(

            curveFunctionSig,

            liquidity,

            uint256(0)

        );



        IERC20(underlying).safeApprove(curve, 0);

        IERC20(underlying).safeApprove(curve, underlyingAmount);

        (bool success, ) = curve.call(callData);

        require(success, "!success");

    }

}

contract UniswapV2ProxyLogic {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    IUniswapV2Factory public constant factory = IUniswapV2Factory(

        0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f

    );

    UniswapRouterV2 public constant router = UniswapRouterV2(

        0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D

    );



    address public constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;



    // babylonian method (https://en.wikipedia.org/wiki/Methods_of_computing_square_roots#Babylonian_method)

    function sqrt(uint256 y) internal pure returns (uint256 z) {

        if (y > 3) {

            z = y;

            uint256 x = y / 2 + 1;

            while (x < z) {

                z = x;

                x = (y / x + x) / 2;

            }

        } else if (y != 0) {

            z = 1;

        }

    }



    function getSwapAmt(uint256 amtA, uint256 resA)

        internal

        pure

        returns (uint256)

    {

        return

            sqrt(amtA.mul(resA.mul(3988000).add(amtA.mul(3988009))))

                .sub(amtA.mul(1997))

                .div(1994);

    }



    // https://blog.alphafinance.io/onesideduniswap/

    // https://github.com/AlphaFinanceLab/alphahomora/blob/88a8dfe4d4fa62b13b40f7983ee2c646f83e63b5/contracts/StrategyAddETHOnly.sol#L39

    // AlphaFinance is gripbook licensed

    function optimalOneSideSupply(

        IUniswapV2Pair pair,

        address from,

        address to

    ) public {

        address[] memory path = new address[](2);



        // 1. Compute optimal amount of WETH to be converted

        (uint256 r0, uint256 r1, ) = pair.getReserves();

        uint256 rIn = pair.token0() == from ? r0 : r1;

        uint256 aIn = getSwapAmt(rIn, IERC20(from).balanceOf(address(this)));



        // 2. Convert that from -> to

        path[0] = from;

        path[1] = to;



        IERC20(from).safeApprove(address(router), 0);

        IERC20(from).safeApprove(address(router), aIn);



        router.swapExactTokensForTokens(aIn, 0, path, address(this), now + 60);

    }



    function swapUniswap(address from, address to) public {

        require(to != address(0));



        address[] memory path;



        if (from == weth || to == weth) {

            path = new address[](2);

            path[0] = from;

            path[1] = to;

        } else {

            path = new address[](3);

            path[0] = from;

            path[1] = weth;

            path[2] = to;

        }



        uint256 amount = IERC20(from).balanceOf(address(this));



        IERC20(from).safeApprove(address(router), 0);

        IERC20(from).safeApprove(address(router), amount);

        router.swapExactTokensForTokens(

            amount,

            0,

            path,

            address(this),

            now + 60

        );

    }



    function removeLiquidity(IUniswapV2Pair pair) public {

        uint256 _balance = pair.balanceOf(address(this));

        pair.approve(address(router), _balance);



        router.removeLiquidity(

            pair.token0(),

            pair.token1(),

            _balance,

            0,

            0,

            address(this),

            now + 60

        );

    }



    function supplyLiquidity(

        address token0,

        address token1

    ) public returns (uint256) {

        // Add liquidity to uniswap

        IERC20(token0).safeApprove(address(router), 0);

        IERC20(token0).safeApprove(

            address(router),

            IERC20(token0).balanceOf(address(this))

        );



        IERC20(token1).safeApprove(address(router), 0);

        IERC20(token1).safeApprove(

            address(router),

            IERC20(token1).balanceOf(address(this))

        );



        (, , uint256 _to) = router.addLiquidity(

            token0,

            token1,

            IERC20(token0).balanceOf(address(this)),

            IERC20(token1).balanceOf(address(this)),

            0,

            0,

            address(this),

            now + 60

        );



        return _to;

    }



    function refundDust(IUniswapV2Pair pair, address recipient) public {

        address token0 = pair.token0();

        address token1 = pair.token1();



        IERC20(token0).safeTransfer(

            recipient,

            IERC20(token0).balanceOf(address(this))

        );

        IERC20(token1).safeTransfer(

            recipient,

            IERC20(token1).balanceOf(address(this))

        );

    }



    function lpTokensToPrimitive(

        IUniswapV2Pair from,

        address to

    ) public {

        if (from.token0() != weth && from.token1() != weth) {

            revert("!from-weth-pair");

        }



        address fromOther = from.token0() == weth ? from.token1() : from.token0();



        // Removes liquidity

        removeLiquidity(from);



        // Swap from WETH to other

        swapUniswap(weth, to);



        // If from is not to, we swap them too

        if (fromOther != to) {

            swapUniswap(fromOther, to);

        }

    }



    function primitiveToLpTokens(

        address from,

        IUniswapV2Pair to,

        address dustRecipient

    ) public {

        if (to.token0() != weth && to.token1() != weth) {

            revert("!to-weth-pair");

        }



        address toOther = to.token0() == weth ? to.token1() : to.token0();



        // Swap to WETH

        swapUniswap(from, weth);



        // Optimal supply from WETH to

        optimalOneSideSupply(to, weth, toOther);



        // Supply tokens

        supplyLiquidity(weth, toOther);



        // Dust

        refundDust(to, dustRecipient);

    }



    function swapUniLPTokens(

        IUniswapV2Pair from,

        IUniswapV2Pair to,

        address dustRecipient

    ) public {

        if (from.token0() != weth && from.token1() != weth) {

            revert("!from-weth-pair");

        }



        if (to.token0() != weth && to.token1() != weth) {

            revert("!to-weth-pair");

        }



        address fromOther = from.token0() == weth

            ? from.token1()

            : from.token0();



        address toOther = to.token0() == weth ? to.token1() : to.token0();



        // Remove weth-<token> pair

        removeLiquidity(from);



        // Swap <token> to WETH

        swapUniswap(fromOther, weth);



        // Optimal supply from WETH to <other-token>

        optimalOneSideSupply(to, weth, toOther);



        // Supply weth-<other-token> pair

        supplyLiquidity(weth, toOther);



        // Refund dust

        refundDust(to, dustRecipient);

    }

}

contract StakingRewards is ReentrancyGuard, Pausable {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    /* ========== STATE VARIABLES ========== */



    IERC20 public rewardsToken;

    IERC20 public stakingToken;

    uint256 public periodFinish = 0;

    uint256 public rewardRate = 0;

    uint256 public rewardsDuration = 7 days;

    uint256 public lastUpdateTime;

    uint256 public rewardPerTokenStored;



    mapping(address => uint256) public userRewardPerTokenPaid;

    mapping(address => uint256) public rewards;



    uint256 private _totalSupply;

    mapping(address => uint256) private _balances;



    /* ========== CONSTRUCTOR ========== */



    constructor(

        address _owner,

        address _rewardsToken,

        address _stakingToken

    ) public Owned(_owner) {

        rewardsToken = IERC20(_rewardsToken);

        stakingToken = IERC20(_stakingToken);

    }



    /* ========== VIEWS ========== */



    function totalSupply() external view returns (uint256) {

        return _totalSupply;

    }



    function balanceOf(address account) external view returns (uint256) {

        return _balances[account];

    }



    function lastTimeRewardApplicable() public view returns (uint256) {

        return min(block.timestamp, periodFinish);

    }



    function rewardPerToken() public view returns (uint256) {

        if (_totalSupply == 0) {

            return rewardPerTokenStored;

        }

        return

            rewardPerTokenStored.add(

                lastTimeRewardApplicable()

                    .sub(lastUpdateTime)

                    .mul(rewardRate)

                    .mul(1e18)

                    .div(_totalSupply)

            );

    }



    function earned(address account) public view returns (uint256) {

        return

            _balances[account]

                .mul(rewardPerToken().sub(userRewardPerTokenPaid[account]))

                .div(1e18)

                .add(rewards[account]);

    }



    function getRewardForDuration() external view returns (uint256) {

        return rewardRate.mul(rewardsDuration);

    }



    function min(uint256 a, uint256 b) public pure returns (uint256) {

        return a < b ? a : b;

    }



    /* ========== MUTATIVE FUNCTIONS ========== */



    function stake(uint256 amount)

        external

        nonReentrant

        notPaused

        updateReward(msg.sender)

    {

        require(amount > 0, "Cannot stake 0");

        _totalSupply = _totalSupply.add(amount);

        _balances[msg.sender] = _balances[msg.sender].add(amount);

        stakingToken.safeTransferFrom(msg.sender, address(this), amount);

        emit Staked(msg.sender, amount);

    }



    function withdraw(uint256 amount)

        public

        nonReentrant

        updateReward(msg.sender)

    {

        require(amount > 0, "Cannot withdraw 0");

        _totalSupply = _totalSupply.sub(amount);

        _balances[msg.sender] = _balances[msg.sender].sub(amount);

        stakingToken.safeTransfer(msg.sender, amount);

        emit Withdrawn(msg.sender, amount);

    }



    function getReward() public nonReentrant updateReward(msg.sender) {

        uint256 reward = rewards[msg.sender];

        if (reward > 0) {

            rewards[msg.sender] = 0;

            rewardsToken.safeTransfer(msg.sender, reward);

            emit RewardPaid(msg.sender, reward);

        }

    }



    function exit() external {

        withdraw(_balances[msg.sender]);

        getReward();

    }



    /* ========== RESTRICTED FUNCTIONS ========== */



    function notifyRewardAmount(uint256 reward)

        external

        onlyOwner

        updateReward(address(0))

    {

        if (block.timestamp >= periodFinish) {

            rewardRate = reward.div(rewardsDuration);

        } else {

            uint256 remaining = periodFinish.sub(block.timestamp);

            uint256 leftover = remaining.mul(rewardRate);

            rewardRate = reward.add(leftover).div(rewardsDuration);

        }



        // Ensure the provided reward amount is not more than the balance in the contract.

        // This keeps the reward rate in the right range, preventing overflows due to

        // very high values of rewardRate in the earned and rewardsPerToken functions;

        // Reward + leftover must be less than 2^256 / 10^18 to avoid overflow.

        uint256 balance = rewardsToken.balanceOf(address(this));

        require(

            rewardRate <= balance.div(rewardsDuration),

            "Provided reward too high"

        );



        lastUpdateTime = block.timestamp;

        periodFinish = block.timestamp.add(rewardsDuration);

        emit RewardAdded(reward);

    }



    // Added to support recovering LP Rewards from other systems such as BAL to be distributed to holders

    function recoverERC20(address tokenAddress, uint256 tokenAmount)

        external

        onlyOwner

    {

        // Cannot recover the staking token or the rewards token

        require(

            tokenAddress != address(stakingToken) &&

                tokenAddress != address(rewardsToken),

            "Cannot withdraw the staking or rewards tokens"

        );

        IERC20(tokenAddress).safeTransfer(owner, tokenAmount);

        emit Recovered(tokenAddress, tokenAmount);

    }



    function setRewardsDuration(uint256 _rewardsDuration) external onlyOwner {

        require(

            block.timestamp > periodFinish,

            "Previous rewards period must be complete before changing the duration for the new period"

        );

        rewardsDuration = _rewardsDuration;

        emit RewardsDurationUpdated(rewardsDuration);

    }



    /* ========== MODIFIERS ========== */



    modifier updateReward(address account) {

        rewardPerTokenStored = rewardPerToken();

        lastUpdateTime = lastTimeRewardApplicable();

        if (account != address(0)) {

            rewards[account] = earned(account);

            userRewardPerTokenPaid[account] = rewardPerTokenStored;

        }

        _;

    }



    /* ========== EVENTS ========== */



    event RewardAdded(uint256 reward);

    event Staked(address indexed user, uint256 amount);

    event Withdrawn(address indexed user, uint256 amount);

    event RewardPaid(address indexed user, uint256 reward);

    event RewardsDurationUpdated(uint256 newDuration);

    event Recovered(address token, uint256 amount);

}

contract CRVLocker {

    using SafeERC20 for IERC20;

    using Address for address;

    using SafeMath for uint256;



    address public constant mintr = 0xd061D61a4d941c39E5453435B6345Dc261C2fcE0;

    address public constant crv = 0xD533a949740bb3306d119CC777fa900bA034cd52;



    address public constant escrow = 0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2;



    address public governance;

    mapping(address => bool) public voters;



    constructor(address _governance) public {

        governance = _governance;

    }



    function getName() external pure returns (string memory) {

        return "CRVLocker";

    }



    function addVoter(address _voter) external {

        require(msg.sender == governance, "!governance");

        voters[_voter] = true;

    }



    function removeVoter(address _voter) external {

        require(msg.sender == governance, "!governance");

        voters[_voter] = false;

    }



    function withdraw(address _asset) external returns (uint256 balance) {

        require(voters[msg.sender], "!voter");

        balance = IERC20(_asset).balanceOf(address(this));

        IERC20(_asset).safeTransfer(msg.sender, balance);

    }



    function createLock(uint256 _value, uint256 _unlockTime) external {

        require(voters[msg.sender] || msg.sender == governance, "!authorized");

        IERC20(crv).safeApprove(escrow, 0);

        IERC20(crv).safeApprove(escrow, _value);

        ICurveVotingEscrow(escrow).create_lock(_value, _unlockTime);

    }



    function increaseAmount(uint256 _value) external {

        require(voters[msg.sender] || msg.sender == governance, "!authorized");

        IERC20(crv).safeApprove(escrow, 0);

        IERC20(crv).safeApprove(escrow, _value);

        ICurveVotingEscrow(escrow).increase_amount(_value);

    }



    function increaseUnlockTime(uint256 _unlockTime) external {

        require(voters[msg.sender] || msg.sender == governance, "!authorized");

        ICurveVotingEscrow(escrow).increase_unlock_time(_unlockTime);

    }



    function release() external {

        require(voters[msg.sender] || msg.sender == governance, "!authorized");

        ICurveVotingEscrow(escrow).withdraw();

    }



    function setGovernance(address _governance) external {

        require(msg.sender == governance, "!governance");

        governance = _governance;

    }



    function execute(

        address to,

        uint256 value,

        bytes calldata data

    ) external returns (bool, bytes memory) {

        require(voters[msg.sender] || msg.sender == governance, "!governance");



        (bool success, bytes memory result) = to.call{value: value}(data);

        require(success, "!execute-success");



        return (success, result);

    }

}

contract SCRVVoter {

    using SafeERC20 for IERC20;

    using Address for address;

    using SafeMath for uint256;



    CRVLocker public crvLocker;



    address public constant want = 0xC25a3A3b969415c80451098fa907EC722572917F;

    address public constant mintr = 0xd061D61a4d941c39E5453435B6345Dc261C2fcE0;

    address public constant crv = 0xD533a949740bb3306d119CC777fa900bA034cd52;

    address public constant snx = 0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F;

    address

        public constant gaugeController = 0x2F50D538606Fa9EDD2B11E2446BEb18C9D5846bB;

    address

        public constant scrvGauge = 0xA90996896660DEcC6E997655E065b23788857849;



    mapping(address => bool) public strategies;

    address public governance;



    constructor(address _governance, address _crvLocker) public {

        governance = _governance;

        crvLocker = CRVLocker(_crvLocker);

    }



    function setGovernance(address _governance) external {

        require(msg.sender == governance, "!governance");

        governance = _governance;

    }



    function approveStrategy(address _strategy) external {

        require(msg.sender == governance, "!governance");

        strategies[_strategy] = true;

    }



    function revokeStrategy(address _strategy) external {

        require(msg.sender == governance, "!governance");

        strategies[_strategy] = false;

    }



    function lock() external {

        crvLocker.increaseAmount(IERC20(crv).balanceOf(address(crvLocker)));

    }



    function vote(address _gauge, uint256 _amount) public {

        require(strategies[msg.sender], "!strategy");

        crvLocker.execute(

            gaugeController,

            0,

            abi.encodeWithSignature(

                "vote_for_gauge_weights(address,uint256)",

                _gauge,

                _amount

            )

        );

    }



    function max() external {

        require(strategies[msg.sender], "!strategy");

        vote(scrvGauge, 10000);

    }



    function withdraw(

        address _gauge,

        address _token,

        uint256 _amount

    ) public returns (uint256) {

        require(strategies[msg.sender], "!strategy");

        uint256 _before = IERC20(_token).balanceOf(address(crvLocker));

        crvLocker.execute(

            _gauge,

            0,

            abi.encodeWithSignature("withdraw(uint256)", _amount)

        );

        uint256 _after = IERC20(_token).balanceOf(address(crvLocker));

        uint256 _net = _after.sub(_before);

        crvLocker.execute(

            _token,

            0,

            abi.encodeWithSignature(

                "transfer(address,uint256)",

                msg.sender,

                _net

            )

        );

        return _net;

    }



    function balanceOf(address _gauge) public view returns (uint256) {

        return IERC20(_gauge).balanceOf(address(crvLocker));

    }



    function withdrawAll(address _gauge, address _token)

        external

        returns (uint256)

    {

        require(strategies[msg.sender], "!strategy");

        return withdraw(_gauge, _token, balanceOf(_gauge));

    }



    function deposit(address _gauge, address _token) external {

        uint256 _balance = IERC20(_token).balanceOf(address(this));

        IERC20(_token).safeTransfer(address(crvLocker), _balance);



        _balance = IERC20(_token).balanceOf(address(crvLocker));

        crvLocker.execute(

            _token,

            0,

            abi.encodeWithSignature("approve(address,uint256)", _gauge, 0)

        );

        crvLocker.execute(

            _token,

            0,

            abi.encodeWithSignature(

                "approve(address,uint256)",

                _gauge,

                _balance

            )

        );

        crvLocker.execute(

            _gauge,

            0,

            abi.encodeWithSignature("deposit(uint256)", _balance)

        );

    }



    function harvest(address _gauge) external {

        require(strategies[msg.sender], "!strategy");

        uint256 _before = IERC20(crv).balanceOf(address(crvLocker));

        crvLocker.execute(

            mintr,

            0,

            abi.encodeWithSignature("mint(address)", _gauge)

        );

        uint256 _after = IERC20(crv).balanceOf(address(crvLocker));

        uint256 _balance = _after.sub(_before);

        crvLocker.execute(

            crv,

            0,

            abi.encodeWithSignature(

                "transfer(address,uint256)",

                msg.sender,

                _balance

            )

        );

    }



    function claimRewards() external {

        require(strategies[msg.sender], "!strategy");



        uint256 _before = IERC20(snx).balanceOf(address(crvLocker));

        crvLocker.execute(scrvGauge, 0, abi.encodeWithSignature("claim_rewards()"));

        uint256 _after = IERC20(snx).balanceOf(address(crvLocker));

        uint256 _balance = _after.sub(_before);



        crvLocker.execute(

            snx,

            0,

            abi.encodeWithSignature(

                "transfer(address,uint256)",

                msg.sender,

                _balance

            )

        );

    }

}

abstract contract StrategyBase {

    using SafeERC20 for IERC20;

    using Address for address;

    using SafeMath for uint256;



    // Perfomance fees - start with 4.5%

    uint256 public performanceTreasuryFee = 450;

    uint256 public constant performanceTreasuryMax = 10000;



    uint256 public performanceDevFee = 0;

    uint256 public constant performanceDevMax = 10000;



    // Withdrawal fee 0.5%

    // - 0.325% to treasury

    // - 0.175% to dev fund

    uint256 public withdrawalTreasuryFee = 325;

    uint256 public constant withdrawalTreasuryMax = 100000;



    uint256 public withdrawalDevFundFee = 175;

    uint256 public constant withdrawalDevFundMax = 100000;



    // Tokens

    address public want;

    address public constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;



    // User accounts

    address public governance;

    address public controller;

    address public strategist;

    address public timelock;



    // Dex

    address public univ2Router2 = 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D;



    constructor(

        address _want,

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    ) public {

        require(_want != address(0));

        require(_governance != address(0));

        require(_strategist != address(0));

        require(_controller != address(0));

        require(_timelock != address(0));



        want = _want;

        governance = _governance;

        strategist = _strategist;

        controller = _controller;

        timelock = _timelock;

    }



    // **** Modifiers **** //



    modifier onlyBenevolent {

        require(

            msg.sender == tx.origin ||

                msg.sender == governance ||

                msg.sender == strategist

        );

        _;

    }



    // **** Views **** //



    function balanceOfWant() public view returns (uint256) {

        return IERC20(want).balanceOf(address(this));

    }



    function balanceOfPool() public virtual view returns (uint256);



    function balanceOf() public view returns (uint256) {

        return balanceOfWant().add(balanceOfPool());

    }



    function getName() external virtual pure returns (string memory);



    // **** Setters **** //



    function setWithdrawalDevFundFee(uint256 _withdrawalDevFundFee) external {

        require(msg.sender == timelock, "!timelock");

        withdrawalDevFundFee = _withdrawalDevFundFee;

    }



    function setWithdrawalTreasuryFee(uint256 _withdrawalTreasuryFee) external {

        require(msg.sender == timelock, "!timelock");

        withdrawalTreasuryFee = _withdrawalTreasuryFee;

    }



    function setPerformanceDevFee(uint256 _performanceDevFee) external {

        require(msg.sender == timelock, "!timelock");

        performanceDevFee = _performanceDevFee;

    }



    function setPerformanceTreasuryFee(uint256 _performanceTreasuryFee)

        external

    {

        require(msg.sender == timelock, "!timelock");

        performanceTreasuryFee = _performanceTreasuryFee;

    }



    function setStrategist(address _strategist) external {

        require(msg.sender == governance, "!governance");

        strategist = _strategist;

    }



    function setGovernance(address _governance) external {

        require(msg.sender == governance, "!governance");

        governance = _governance;

    }



    function setTimelock(address _timelock) external {

        require(msg.sender == timelock, "!timelock");

        timelock = _timelock;

    }



    function setController(address _controller) external {

        require(msg.sender == timelock, "!timelock");

        controller = _controller;

    }



    // **** State mutations **** //

    function deposit() public virtual;



    // Controller only function for creating additional rewards from dust

    function withdraw(IERC20 _asset) external returns (uint256 balance) {

        require(msg.sender == controller, "!controller");

        require(want != address(_asset), "want");

        balance = _asset.balanceOf(address(this));

        _asset.safeTransfer(controller, balance);

    }



    // Withdraw partial funds, normally used with a jar withdrawal

    function withdraw(uint256 _amount) external {

        require(msg.sender == controller, "!controller");

        uint256 _balance = IERC20(want).balanceOf(address(this));

        if (_balance < _amount) {

            _amount = _withdrawSome(_amount.sub(_balance));

            _amount = _amount.add(_balance);

        }



        uint256 _feeDev = _amount.mul(withdrawalDevFundFee).div(

            withdrawalDevFundMax

        );

        IERC20(want).safeTransfer(IController(controller).devfund(), _feeDev);



        uint256 _feeTreasury = _amount.mul(withdrawalTreasuryFee).div(

            withdrawalTreasuryMax

        );

        IERC20(want).safeTransfer(

            IController(controller).treasury(),

            _feeTreasury

        );



        address _jar = IController(controller).jars(address(want));

        require(_jar != address(0), "!jar"); // additional protection so we don't burn the funds



        IERC20(want).safeTransfer(_jar, _amount.sub(_feeDev).sub(_feeTreasury));

    }



    // Withdraw funds, used to swap between strategies

    function withdrawForSwap(uint256 _amount)

        external

        returns (uint256 balance)

    {

        require(msg.sender == controller, "!controller");

        _withdrawSome(_amount);



        balance = IERC20(want).balanceOf(address(this));



        address _jar = IController(controller).jars(address(want));

        require(_jar != address(0), "!jar");

        IERC20(want).safeTransfer(_jar, balance);

    }



    // Withdraw all funds, normally used when migrating strategies

    function withdrawAll() external returns (uint256 balance) {

        require(msg.sender == controller, "!controller");

        _withdrawAll();



        balance = IERC20(want).balanceOf(address(this));



        address _jar = IController(controller).jars(address(want));

        require(_jar != address(0), "!jar"); // additional protection so we don't burn the funds

        IERC20(want).safeTransfer(_jar, balance);

    }



    function _withdrawAll() internal {

        _withdrawSome(balanceOfPool());

    }



    function _withdrawSome(uint256 _amount) internal virtual returns (uint256);



    function harvest() public virtual;



    // **** Emergency functions ****



    function execute(address _target, bytes memory _data)

        public

        payable

        returns (bytes memory response)

    {

        require(msg.sender == timelock, "!timelock");

        require(_target != address(0), "!target");



        // call contract in current context

        assembly {

            let succeeded := delegatecall(

                sub(gas(), 5000),

                _target,

                add(_data, 0x20),

                mload(_data),

                0,

                0

            )

            let size := returndatasize()



            response := mload(0x40)

            mstore(

                0x40,

                add(response, and(add(add(size, 0x20), 0x1f), not(0x1f)))

            )

            mstore(response, size)

            returndatacopy(add(response, 0x20), 0, size)



            switch iszero(succeeded)

                case 1 {

                    // throw if delegatecall failed

                    revert(add(response, 0x20), size)

                }

        }

    }



    // **** Internal functions ****

    function _swapUniswap(

        address _from,

        address _to,

        uint256 _amount

    ) internal {

        require(_to != address(0));



        // Swap with uniswap

        IERC20(_from).safeApprove(univ2Router2, 0);

        IERC20(_from).safeApprove(univ2Router2, _amount);



        address[] memory path;



        if (_from == weth || _to == weth) {

            path = new address[](2);

            path[0] = _from;

            path[1] = _to;

        } else {

            path = new address[](3);

            path[0] = _from;

            path[1] = weth;

            path[2] = _to;

        }



        UniswapRouterV2(univ2Router2).swapExactTokensForTokens(

            _amount,

            0,

            path,

            address(this),

            now.add(60)

        );

    }



    function _distributePerformanceFeesAndDeposit() internal {

        uint256 _want = IERC20(want).balanceOf(address(this));



        if (_want > 0) {

            // Treasury fees

            IERC20(want).safeTransfer(

                IController(controller).treasury(),

                _want.mul(performanceTreasuryFee).div(performanceTreasuryMax)

            );



            // Performance fee

            IERC20(want).safeTransfer(

                IController(controller).devfund(),

                _want.mul(performanceDevFee).div(performanceDevMax)

            );



            deposit();

        }

    }

}

abstract contract StrategyCurveBase is StrategyBase {

    // curve dao

    address public gauge;

    address public curve;

    address public mintr = 0xd061D61a4d941c39E5453435B6345Dc261C2fcE0;



    // stablecoins

    address public dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    address public usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    address public usdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    address public susd = 0x57Ab1ec28D129707052df4dF418D58a2D46d5f51;



    // bitcoins

    address public wbtc = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    address public renbtc = 0xEB4C2781e4ebA804CE9a9803C67d0893436bB27D;



    // rewards

    address public crv = 0xD533a949740bb3306d119CC777fa900bA034cd52;



    // How much CRV tokens to keep

    uint256 public keepCRV = 0;

    uint256 public keepCRVMax = 10000;



    constructor(

        address _curve,

        address _gauge,

        address _want,

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyBase(_want, _governance, _strategist, _controller, _timelock)

    {

        curve = _curve;

        gauge = _gauge;

    }



    // **** Getters ****



    function balanceOfPool() public override view returns (uint256) {

        return ICurveGauge(gauge).balanceOf(address(this));

    }



    function getHarvestable() external returns (uint256) {

        return ICurveGauge(gauge).claimable_tokens(address(this));

    }



    function getMostPremium() public virtual view returns (address, uint256);



    // **** Setters ****



    function setKeepCRV(uint256 _keepCRV) external {

        require(msg.sender == governance, "!governance");

        keepCRV = _keepCRV;

    }



    // **** State Mutation functions ****



    function deposit() public override {

        uint256 _want = IERC20(want).balanceOf(address(this));

        if (_want > 0) {

            IERC20(want).safeApprove(gauge, 0);

            IERC20(want).safeApprove(gauge, _want);

            ICurveGauge(gauge).deposit(_want);

        }

    }



    function _withdrawSome(uint256 _amount)

        internal

        override

        returns (uint256)

    {

        ICurveGauge(gauge).withdraw(_amount);

        return _amount;

    }

}

abstract contract StrategyStakingRewardsBase is StrategyBase {

    address public rewards;



    // **** Getters ****

    constructor(

        address _rewards,

        address _want,

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyBase(_want, _governance, _strategist, _controller, _timelock)

    {

        rewards = _rewards;

    }



    function balanceOfPool() public override view returns (uint256) {

        return IStakingRewards(rewards).balanceOf(address(this));

    }



    function getHarvestable() external view returns (uint256) {

        return IStakingRewards(rewards).earned(address(this));

    }



    // **** Setters ****



    function deposit() public override {

        uint256 _want = IERC20(want).balanceOf(address(this));

        if (_want > 0) {

            IERC20(want).safeApprove(rewards, 0);

            IERC20(want).safeApprove(rewards, _want);

            IStakingRewards(rewards).stake(_want);

        }

    }



    function _withdrawSome(uint256 _amount)

        internal

        override

        returns (uint256)

    {

        IStakingRewards(rewards).withdraw(_amount);

        return _amount;

    }

}

abstract contract StrategyUniFarmBase is StrategyStakingRewardsBase {

    // Token addresses

    address public uni = 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984;



    // WETH/<token1> pair

    address public token1;



    // How much UNI tokens to keep?

    uint256 public keepUNI = 0;

    uint256 public constant keepUNIMax = 10000;



    constructor(

        address _token1,

        address _rewards,

        address _lp,

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyStakingRewardsBase(

            _rewards,

            _lp,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {

        token1 = _token1;

    }



    // **** Setters ****



    function setKeepUNI(uint256 _keepUNI) external {

        require(msg.sender == timelock, "!timelock");

        keepUNI = _keepUNI;

    }



    // **** State Mutations ****



    function harvest() public override onlyBenevolent {

        // Anyone can harvest it at any given time.

        // I understand the possibility of being frontrun

        // But ETH is a dark forest, and I wanna see how this plays out

        // i.e. will be be heavily frontrunned?

        //      if so, a new strategy will be deployed.



        // Collects UNI tokens

        IStakingRewards(rewards).getReward();

        uint256 _uni = IERC20(uni).balanceOf(address(this));

        if (_uni > 0) {

            // 10% is locked up for future gov

            uint256 _keepUNI = _uni.mul(keepUNI).div(keepUNIMax);

            IERC20(uni).safeTransfer(

                IController(controller).treasury(),

                _keepUNI

            );

            _swapUniswap(uni, weth, _uni.sub(_keepUNI));

        }



        // Swap half WETH for DAI

        uint256 _weth = IERC20(weth).balanceOf(address(this));

        if (_weth > 0) {

            _swapUniswap(weth, token1, _weth.div(2));

        }



        // Adds in liquidity for ETH/DAI

        _weth = IERC20(weth).balanceOf(address(this));

        uint256 _token1 = IERC20(token1).balanceOf(address(this));

        if (_weth > 0 && _token1 > 0) {

            IERC20(weth).safeApprove(univ2Router2, 0);

            IERC20(weth).safeApprove(univ2Router2, _weth);



            IERC20(token1).safeApprove(univ2Router2, 0);

            IERC20(token1).safeApprove(univ2Router2, _token1);



            UniswapRouterV2(univ2Router2).addLiquidity(

                weth,

                token1,

                _weth,

                _token1,

                0,

                0,

                address(this),

                now + 60

            );



            // Donates DUST

            IERC20(weth).transfer(

                IController(controller).treasury(),

                IERC20(weth).balanceOf(address(this))

            );

            IERC20(token1).safeTransfer(

                IController(controller).treasury(),

                IERC20(token1).balanceOf(address(this))

            );

        }



        // We want to get back UNI LP tokens

        _distributePerformanceFeesAndDeposit();

    }

}

contract StrategyUniEthDaiLpV4 is StrategyUniFarmBase {

    // Token addresses

    address public uni_rewards = 0xa1484C3aa22a66C62b77E0AE78E15258bd0cB711;

    address public uni_eth_dai_lp = 0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11;

    address public dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyUniFarmBase(

            dai,

            uni_rewards,

            uni_eth_dai_lp,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getName() external override pure returns (string memory) {

        return "StrategyUniEthDaiLpV4";

    }

}

contract StrategyUniEthUsdcLpV4 is StrategyUniFarmBase {

    // Token addresses

    address public uni_rewards = 0x7FBa4B8Dc5E7616e59622806932DBea72537A56b;

    address public uni_eth_usdc_lp = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;

    address public usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyUniFarmBase(

            usdc,

            uni_rewards,

            uni_eth_usdc_lp,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getName() external override pure returns (string memory) {

        return "StrategyUniEthUsdcLpV4";

    }

}

contract StrategyUniEthUsdtLpV4 is StrategyUniFarmBase {

    // Token addresses

    address public uni_rewards = 0x6C3e4cb2E96B01F4b866965A91ed4437839A121a;

    address public uni_eth_usdt_lp = 0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852;

    address public usdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyUniFarmBase(

            usdt,

            uni_rewards,

            uni_eth_usdt_lp,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getName() external override pure returns (string memory) {

        return "StrategyUniEthUsdtLpV4";

    }

}

contract StrategyUniEthWBtcLpV2 is StrategyUniFarmBase {

    // Token addresses

    address public uni_rewards = 0xCA35e32e7926b96A9988f61d510E038108d8068e;

    address public uni_eth_wbtc_lp = 0xBb2b8038a1640196FbE3e38816F3e67Cba72D940;

    address public wbtc = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyUniFarmBase(

            wbtc,

            uni_rewards,

            uni_eth_wbtc_lp,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getName() external override pure returns (string memory) {

        return "StrategyUniEthWBtcLpV2";

    }

}

interface Hevm {

    function warp(uint256) external;

    function roll(uint x) external;

    function store(address c, bytes32 loc, bytes32 val) external;

}

contract MockERC20 is ERC20 {

    constructor(string memory name, string memory symbol)

        public

        ERC20(name, symbol)

    {}



    function mint(address recipient, uint256 amount) public {

        _mint(recipient, amount);

    }

}

contract DSTest {

    event eventListener          (address target, bool exact);

    event logs                   (bytes);

    event log_bytes32            (bytes32);

    event log_named_address      (bytes32 key, address val);

    event log_named_bytes32      (bytes32 key, bytes32 val);

    event log_named_decimal_int  (bytes32 key, int val, uint decimals);

    event log_named_decimal_uint (bytes32 key, uint val, uint decimals);

    event log_named_int          (bytes32 key, int val);

    event log_named_uint         (bytes32 key, uint val);

    event log_named_string       (bytes32 key, string val);



    bool public IS_TEST;

    bool public failed;



    constructor() internal {

        IS_TEST = true;

    }



    function fail() internal {

        failed = true;

    }



    function expectEventsExact(address target) internal {

        emit eventListener(target, true);

    }



    modifier logs_gas() {

        uint startGas = gasleft();

        _;

        uint endGas = gasleft();

        emit log_named_uint("gas", startGas - endGas);

    }



    function assertTrue(bool condition) internal {

        if (!condition) {

            emit log_bytes32("Assertion failed");

            fail();

        }

    }



    function assertEq(address a, address b) internal {

        if (a != b) {

            emit log_bytes32("Error: Wrong `address' value");

            emit log_named_address("  Expected", b);

            emit log_named_address("    Actual", a);

            fail();

        }

    }



    function assertEq32(bytes32 a, bytes32 b) internal {

        assertEq(a, b);

    }



    function assertEq(bytes32 a, bytes32 b) internal {

        if (a != b) {

            emit log_bytes32("Error: Wrong `bytes32' value");

            emit log_named_bytes32("  Expected", b);

            emit log_named_bytes32("    Actual", a);

            fail();

        }

    }



    function assertEqDecimal(int a, int b, uint decimals) internal {

        if (a != b) {

            emit log_bytes32("Error: Wrong fixed-point decimal");

            emit log_named_decimal_int("  Expected", b, decimals);

            emit log_named_decimal_int("    Actual", a, decimals);

            fail();

        }

    }



    function assertEqDecimal(uint a, uint b, uint decimals) internal {

        if (a != b) {

            emit log_bytes32("Error: Wrong fixed-point decimal");

            emit log_named_decimal_uint("  Expected", b, decimals);

            emit log_named_decimal_uint("    Actual", a, decimals);

            fail();

        }

    }



    function assertEq(int a, int b) internal {

        if (a != b) {

            emit log_bytes32("Error: Wrong `int' value");

            emit log_named_int("  Expected", b);

            emit log_named_int("    Actual", a);

            fail();

        }

    }



    function assertEq(uint a, uint b) internal {

        if (a != b) {

            emit log_bytes32("Error: Wrong `uint' value");

            emit log_named_uint("  Expected", b);

            emit log_named_uint("    Actual", a);

            fail();

        }

    }



    function assertEq(string memory a, string memory b) internal {

        if (keccak256(abi.encodePacked(a)) != keccak256(abi.encodePacked(b))) {

            emit log_bytes32("Error: Wrong `string' value");

            emit log_named_string("  Expected", b);

            emit log_named_string("    Actual", a);

            fail();

        }

    }



    function assertEq0(bytes memory a, bytes memory b) internal {

        bool ok = true;



        if (a.length == b.length) {

            for (uint i = 0; i < a.length; i++) {

                if (a[i] != b[i]) {

                    ok = false;

                }

            }

        } else {

            ok = false;

        }



        if (!ok) {

            emit log_bytes32("Error: Wrong `bytes' value");

            emit log_named_bytes32("  Expected", "[cannot show `bytes' value]");

            emit log_named_bytes32("  Actual", "[cannot show `bytes' value]");

            fail();

        }

    }

}

contract User {

    function execute(

        address target,

        uint256 value,

        string memory signature,

        bytes memory data

    ) public payable returns (bytes memory) {

        bytes memory callData;



        if (bytes(signature).length == 0) {

            callData = data;

        } else {

            callData = abi.encodePacked(

                bytes4(keccak256(bytes(signature))),

                data

            );

        }



        (bool success, bytes memory returnData) = target.call{value: value}(

            callData

        );

        require(success, "!user-execute");



        return returnData;

    }

}

contract StakngRewardsTest is DSTest {

    using SafeMath for uint256;



    MockERC20 stakingToken;

    MockERC20 rewardsToken;



    StakingRewards stakingRewards;



    address owner;



    Hevm hevm = Hevm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);



    function setUp() public {

        owner = address(this);



        stakingToken = new MockERC20("staking", "STAKE");

        rewardsToken = new MockERC20("rewards", "RWD");



        stakingRewards = new StakingRewards(

            owner,

            address(rewardsToken),

            address(stakingToken)

        );

    }



    function test_staking() public {

        uint256 stakeAmount = 100 ether;

        uint256 rewardAmount = 100 ether;



        stakingToken.mint(owner, stakeAmount);

        rewardsToken.mint(owner, rewardAmount);



        stakingToken.approve(address(stakingRewards), stakeAmount);

        stakingRewards.stake(stakeAmount);



        // // Make sure nothing is earned

        uint256 _before = stakingRewards.earned(owner);

        assertEq(_before, 0);



        // Fast forward

        hevm.warp(block.timestamp + 1 days);



        // No funds until we actually supply funds

        uint256 _after = stakingRewards.earned(owner);

        assertEq(_after, _before);



        // Give rewards

        rewardsToken.transfer(address(stakingRewards), rewardAmount);

        stakingRewards.notifyRewardAmount(rewardAmount);



        uint256 _rateBefore = stakingRewards.getRewardForDuration();

        assertTrue(_rateBefore > 0);



        // Fast forward

        _before = stakingRewards.earned(owner);

        hevm.warp(block.timestamp + 1 days);

        _after = stakingRewards.earned(owner);

        assertTrue(_after > _before);

        assertTrue(_after > 0);



        // Add more rewards, rate should increase

        rewardsToken.mint(owner, rewardAmount);

        rewardsToken.transfer(address(stakingRewards), rewardAmount);

        stakingRewards.notifyRewardAmount(rewardAmount);



        uint256 _rateAfter = stakingRewards.getRewardForDuration();

        assertTrue(_rateAfter > _rateBefore);



        // Warp to period finish

        hevm.warp(stakingRewards.periodFinish() + 1 days);



        // Retrieve tokens

        stakingRewards.getReward();



        _before = stakingRewards.earned(owner);

        hevm.warp(block.timestamp + 1 days);

        _after = stakingRewards.earned(owner);



        // Earn 0 after period finished

        assertEq(_before, 0);

        assertEq(_after, 0);

    }

}

contract UniCurveConverter {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    UniswapRouterV2 public router = UniswapRouterV2(

        0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D

    );



    // Stablecoins

    address public constant dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    address public constant usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    address public constant usdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    address public constant susd = 0x57Ab1ec28D129707052df4dF418D58a2D46d5f51;



    // Wrapped stablecoins

    address public constant scrv = 0xC25a3A3b969415c80451098fa907EC722572917F;



    // Weth

    address public constant weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;



    // susd v2 pool

    ICurveFi_4 public curve = ICurveFi_4(

        0xA5407eAE9Ba41422680e2e00537571bcC53efBfD

    );



    // UNI LP -> Curve LP

    // Assume th

    function convert(address _lp, uint256 _amount) public {

        // Get LP Tokens

        IERC20(_lp).safeTransferFrom(msg.sender, address(this), _amount);



        // Get Uniswap pair

        IUniswapV2Pair fromPair = IUniswapV2Pair(_lp);



        // Only for WETH/<TOKEN> pairs

        if (!(fromPair.token0() == weth || fromPair.token1() == weth)) {

            revert("!eth-from");

        }



        // Remove liquidity

        IERC20(_lp).safeApprove(address(router), 0);

        IERC20(_lp).safeApprove(address(router), _amount);

        router.removeLiquidity(

            fromPair.token0(),

            fromPair.token1(),

            _amount,

            0,

            0,

            address(this),

            now + 60

        );



        // Most premium stablecoin

        (address premiumStablecoin, ) = getMostPremium();



        // Convert weth -> most premium stablecoin

        address[] memory path = new address[](2);

        path[0] = weth;

        path[1] = premiumStablecoin;



        IERC20(weth).safeApprove(address(router), 0);

        IERC20(weth).safeApprove(address(router), uint256(-1));

        router.swapExactTokensForTokens(

            IERC20(weth).balanceOf(address(this)),

            0,

            path,

            address(this),

            now + 60

        );



        // Convert the other asset into stablecoin if its not a stablecoin

        address _from = fromPair.token0() != weth

            ? fromPair.token0()

            : fromPair.token1();



        if (_from != dai && _from != usdc && _from != usdt && _from != susd) {

            path = new address[](3);

            path[0] = _from;

            path[1] = weth;

            path[2] = premiumStablecoin;



            IERC20(_from).safeApprove(address(router), 0);

            IERC20(_from).safeApprove(address(router), uint256(-1));

            router.swapExactTokensForTokens(

                IERC20(_from).balanceOf(address(this)),

                0,

                path,

                address(this),

                now + 60

            );

        }



        // Add liquidity to curve

        IERC20(dai).safeApprove(address(curve), 0);

        IERC20(dai).safeApprove(address(curve), uint256(-1));



        IERC20(usdc).safeApprove(address(curve), 0);

        IERC20(usdc).safeApprove(address(curve), uint256(-1));



        IERC20(usdt).safeApprove(address(curve), 0);

        IERC20(usdt).safeApprove(address(curve), uint256(-1));



        IERC20(susd).safeApprove(address(curve), 0);

        IERC20(susd).safeApprove(address(curve), uint256(-1));



        curve.add_liquidity(

            [

                IERC20(dai).balanceOf(address(this)),

                IERC20(usdc).balanceOf(address(this)),

                IERC20(usdt).balanceOf(address(this)),

                IERC20(susd).balanceOf(address(this))

            ],

            0

        );



        // Sends token back to user

        IERC20(scrv).transfer(

            msg.sender,

            IERC20(scrv).balanceOf(address(this))

        );

    }



    function getMostPremium() public view returns (address, uint256) {

        uint256[] memory balances = new uint256[](4);

        balances[0] = ICurveFi_4(curve).balances(0); // DAI

        balances[1] = ICurveFi_4(curve).balances(1).mul(10**12); // USDC

        balances[2] = ICurveFi_4(curve).balances(2).mul(10**12); // USDT

        balances[3] = ICurveFi_4(curve).balances(3); // sUSD



        // DAI

        if (

            balances[0] < balances[1] &&

            balances[0] < balances[2] &&

            balances[0] < balances[3]

        ) {

            return (dai, 0);

        }



        // USDC

        if (

            balances[1] < balances[0] &&

            balances[1] < balances[2] &&

            balances[1] < balances[3]

        ) {

            return (usdc, 1);

        }



        // USDT

        if (

            balances[2] < balances[0] &&

            balances[2] < balances[1] &&

            balances[2] < balances[3]

        ) {

            return (usdt, 2);

        }



        // SUSD

        if (

            balances[3] < balances[0] &&

            balances[3] < balances[1] &&

            balances[3] < balances[2]

        ) {

            return (susd, 3);

        }



        // If they're somehow equal, we just want DAI

        return (dai, 0);

    }

}

interface IERC20 {

    function totalSupply() external view returns (uint256);



    function balanceOf(address account) external view returns (uint256);



    function transfer(address recipient, uint256 amount)

        external

        returns (bool);



    function allowance(address owner, address spender)

        external

        view

        returns (uint256);



    function approve(address spender, uint256 amount) external returns (bool);



    function transferFrom(

        address sender,

        address recipient,

        uint256 amount

    ) external returns (bool);



    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(

        address indexed owner,

        address indexed spender,

        uint256 value

    );

}

interface MasterChef {

    function userInfo(uint256, address)

        external

        view

        returns (uint256, uint256);

}

contract PickleVoteProxy {

    // ETH/PICKLE token

    IERC20 public constant votes = IERC20(

        0xdc98556Ce24f007A5eF6dC1CE96322d65832A819

    );



    // Pickle's masterchef contract

    MasterChef public constant chef = MasterChef(

        0xbD17B1ce622d73bD438b9E658acA5996dc394b0d

    );



    // Pool 0 is the ETH/PICKLE pool

    uint256 public constant pool = uint256(0);



    // Using 9 decimals as we're square rooting the votes

    function decimals() external pure returns (uint8) {

        return uint8(9);

    }



    function name() external pure returns (string memory) {

        return "PICKLEs In The Citadel";

    }



    function symbol() external pure returns (string memory) {

        return "PICKLE C";

    }



    function totalSupply() external view returns (uint256) {

        return sqrt(votes.totalSupply());

    }



    function balanceOf(address _voter) external view returns (uint256) {

        (uint256 _votes, ) = chef.userInfo(pool, _voter);

        return sqrt(_votes);

    }



    function sqrt(uint256 x) public pure returns (uint256 y) {

        uint256 z = (x + 1) / 2;

        y = x;

        while (z < y) {

            y = z;

            z = (x / z + z) / 2;

        }

    }



    constructor() public {}

}

contract MasterChef is Ownable {

    using SafeMath for uint256;

    using SafeERC20 for IERC20;



    // Info of each user.

    struct UserInfo {

        uint256 amount; // How many LP tokens the user has provided.

        uint256 rewardDebt; // Reward debt. See explanation below.

        //

        // We do some fancy math here. Basically, any point in time, the amount of PICKLEs

        // entitled to a user but is pending to be distributed is:

        //

        //   pending reward = (user.amount * pool.accPicklePerShare) - user.rewardDebt

        //

        // Whenever a user deposits or withdraws LP tokens to a pool. Here's what happens:

        //   1. The pool's `accPicklePerShare` (and `lastRewardBlock`) gets updated.

        //   2. User receives the pending reward sent to his/her address.

        //   3. User's `amount` gets updated.

        //   4. User's `rewardDebt` gets updated.

    }



    // Info of each pool.

    struct PoolInfo {

        IERC20 lpToken; // Address of LP token contract.

        uint256 allocPoint; // How many allocation points assigned to this pool. PICKLEs to distribute per block.

        uint256 lastRewardBlock; // Last block number that PICKLEs distribution occurs.

        uint256 accPicklePerShare; // Accumulated PICKLEs per share, times 1e12. See below.

    }



    // The PICKLE TOKEN!

    PickleToken public pickle;

    // Dev fund (2%, initially)

    uint256 public devFundDivRate = 50;

    // Dev address.

    address public devaddr;

    // Block number when bonus PICKLE period ends.

    uint256 public bonusEndBlock;

    // PICKLE tokens created per block.

    uint256 public picklePerBlock;

    // Bonus muliplier for early pickle makers.

    uint256 public constant BONUS_MULTIPLIER = 10;



    // Info of each pool.

    PoolInfo[] public poolInfo;

    // Info of each user that stakes LP tokens.

    mapping(uint256 => mapping(address => UserInfo)) public userInfo;

    // Total allocation points. Must be the sum of all allocation points in all pools.

    uint256 public totalAllocPoint = 0;

    // The block number when PICKLE mining starts.

    uint256 public startBlock;



    // Events

    event Recovered(address token, uint256 amount);

    event Deposit(address indexed user, uint256 indexed pid, uint256 amount);

    event Withdraw(address indexed user, uint256 indexed pid, uint256 amount);

    event EmergencyWithdraw(

        address indexed user,

        uint256 indexed pid,

        uint256 amount

    );



    constructor(

        PickleToken _pickle,

        address _devaddr,

        uint256 _picklePerBlock,

        uint256 _startBlock,

        uint256 _bonusEndBlock

    ) public {

        pickle = _pickle;

        devaddr = _devaddr;

        picklePerBlock = _picklePerBlock;

        bonusEndBlock = _bonusEndBlock;

        startBlock = _startBlock;

    }



    function poolLength() external view returns (uint256) {

        return poolInfo.length;

    }



    // Add a new lp to the pool. Can only be called by the owner.

    // XXX DO NOT add the same LP token more than once. Rewards will be messed up if you do.

    function add(

        uint256 _allocPoint,

        IERC20 _lpToken,

        bool _withUpdate

    ) public onlyOwner {

        if (_withUpdate) {

            massUpdatePools();

        }

        uint256 lastRewardBlock = block.number > startBlock

            ? block.number

            : startBlock;

        totalAllocPoint = totalAllocPoint.add(_allocPoint);

        poolInfo.push(

            PoolInfo({

                lpToken: _lpToken,

                allocPoint: _allocPoint,

                lastRewardBlock: lastRewardBlock,

                accPicklePerShare: 0

            })

        );

    }



    // Update the given pool's PICKLE allocation point. Can only be called by the owner.

    function set(

        uint256 _pid,

        uint256 _allocPoint,

        bool _withUpdate

    ) public onlyOwner {

        if (_withUpdate) {

            massUpdatePools();

        }

        totalAllocPoint = totalAllocPoint.sub(poolInfo[_pid].allocPoint).add(

            _allocPoint

        );

        poolInfo[_pid].allocPoint = _allocPoint;

    }



    // Return reward multiplier over the given _from to _to block.

    function getMultiplier(uint256 _from, uint256 _to)

        public

        view

        returns (uint256)

    {

        if (_to <= bonusEndBlock) {

            return _to.sub(_from).mul(BONUS_MULTIPLIER);

        } else if (_from >= bonusEndBlock) {

            return _to.sub(_from);

        } else {

            return

                bonusEndBlock.sub(_from).mul(BONUS_MULTIPLIER).add(

                    _to.sub(bonusEndBlock)

                );

        }

    }



    // View function to see pending PICKLEs on frontend.

    function pendingPickle(uint256 _pid, address _user)

        external

        view

        returns (uint256)

    {

        PoolInfo storage pool = poolInfo[_pid];

        UserInfo storage user = userInfo[_pid][_user];

        uint256 accPicklePerShare = pool.accPicklePerShare;

        uint256 lpSupply = pool.lpToken.balanceOf(address(this));

        if (block.number > pool.lastRewardBlock && lpSupply != 0) {

            uint256 multiplier = getMultiplier(

                pool.lastRewardBlock,

                block.number

            );

            uint256 pickleReward = multiplier

                .mul(picklePerBlock)

                .mul(pool.allocPoint)

                .div(totalAllocPoint);

            accPicklePerShare = accPicklePerShare.add(

                pickleReward.mul(1e12).div(lpSupply)

            );

        }

        return

            user.amount.mul(accPicklePerShare).div(1e12).sub(user.rewardDebt);

    }



    // Update reward vairables for all pools. Be careful of gas spending!

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

        uint256 multiplier = getMultiplier(pool.lastRewardBlock, block.number);

        uint256 pickleReward = multiplier

            .mul(picklePerBlock)

            .mul(pool.allocPoint)

            .div(totalAllocPoint);

        pickle.mint(devaddr, pickleReward.div(devFundDivRate));

        pickle.mint(address(this), pickleReward);

        pool.accPicklePerShare = pool.accPicklePerShare.add(

            pickleReward.mul(1e12).div(lpSupply)

        );

        pool.lastRewardBlock = block.number;

    }



    // Deposit LP tokens to MasterChef for PICKLE allocation.

    function deposit(uint256 _pid, uint256 _amount) public {

        PoolInfo storage pool = poolInfo[_pid];

        UserInfo storage user = userInfo[_pid][msg.sender];

        updatePool(_pid);

        if (user.amount > 0) {

            uint256 pending = user

                .amount

                .mul(pool.accPicklePerShare)

                .div(1e12)

                .sub(user.rewardDebt);

            safePickleTransfer(msg.sender, pending);

        }

        pool.lpToken.safeTransferFrom(

            address(msg.sender),

            address(this),

            _amount

        );

        user.amount = user.amount.add(_amount);

        user.rewardDebt = user.amount.mul(pool.accPicklePerShare).div(1e12);

        emit Deposit(msg.sender, _pid, _amount);

    }



    // Withdraw LP tokens from MasterChef.

    function withdraw(uint256 _pid, uint256 _amount) public {

        PoolInfo storage pool = poolInfo[_pid];

        UserInfo storage user = userInfo[_pid][msg.sender];

        require(user.amount >= _amount, "withdraw: not good");

        updatePool(_pid);

        uint256 pending = user.amount.mul(pool.accPicklePerShare).div(1e12).sub(

            user.rewardDebt

        );

        safePickleTransfer(msg.sender, pending);

        user.amount = user.amount.sub(_amount);

        user.rewardDebt = user.amount.mul(pool.accPicklePerShare).div(1e12);

        pool.lpToken.safeTransfer(address(msg.sender), _amount);

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



    // Safe pickle transfer function, just in case if rounding error causes pool to not have enough PICKLEs.

    function safePickleTransfer(address _to, uint256 _amount) internal {

        uint256 pickleBal = pickle.balanceOf(address(this));

        if (_amount > pickleBal) {

            pickle.transfer(_to, pickleBal);

        } else {

            pickle.transfer(_to, _amount);

        }

    }



    // Update dev address by the previous dev.

    function dev(address _devaddr) public {

        require(msg.sender == devaddr, "dev: wut?");

        devaddr = _devaddr;

    }



    // **** Additional functions separate from the original masterchef contract ****



    function setPicklePerBlock(uint256 _picklePerBlock) public onlyOwner {

        require(_picklePerBlock > 0, "!picklePerBlock-0");



        picklePerBlock = _picklePerBlock;

    }



    function setBonusEndBlock(uint256 _bonusEndBlock) public onlyOwner {

        bonusEndBlock = _bonusEndBlock;

    }



    function setDevFundDivRate(uint256 _devFundDivRate) public onlyOwner {

        require(_devFundDivRate > 0, "!devFundDivRate-0");

        devFundDivRate = _devFundDivRate;

    }

}

contract PickleToken is ERC20("PickleToken", "PICKLE"), Ownable {

    /// @notice Creates `_amount` token to `_to`. Must only be called by the owner (MasterChef).

    function mint(address _to, uint256 _amount) public onlyOwner {

        _mint(_to, _amount);

    }

}

interface IJar is IERC20 {

    function token() external view returns (address);



    function claimInsurance() external; // NOTE: Only yDelegatedVault implements this



    function getRatio() external view returns (uint256);



    function deposit(uint256) external;



    function withdraw(uint256) external;



    function earn() external;



    function decimals() external view returns (uint8);

}

contract StrategyCmpdDaiV2 is StrategyBase, Exponential {

    address

        public constant comptroller = 0x3d9819210A31b4961b30EF54bE2aeD79B9c9Cd3B;

    address public constant lens = 0xd513d22422a3062Bd342Ae374b4b9c20E0a9a074;

    address public constant dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    address public constant comp = 0xc00e94Cb662C3520282E6f5717214004A7f26888;

    address public constant cdai = 0x5d3a536E4D6DbD6114cc1Ead35777bAB948E3643;

    address public constant cether = 0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5;



    // Require a 0.1 buffer between

    // market collateral factor and strategy's collateral factor

    // when leveraging

    uint256 colFactorLeverageBuffer = 100;

    uint256 colFactorLeverageBufferMax = 1000;



    // Allow a 0.05 buffer

    // between market collateral factor and strategy's collateral factor

    // until we have to deleverage

    // This is so we can hit max leverage and keep accruing interest

    uint256 colFactorSyncBuffer = 50;

    uint256 colFactorSyncBufferMax = 1000;



    // Keeper bots

    // Maintain leverage within buffer

    mapping(address => bool) keepers;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyBase(dai, _governance, _strategist, _controller, _timelock)

    {

        // Enter cDAI Market

        address[] memory ctokens = new address[](1);

        ctokens[0] = cdai;

        IComptroller(comptroller).enterMarkets(ctokens);

    }



    // **** Modifiers **** //



    modifier onlyKeepers {

        require(

            keepers[msg.sender] ||

                msg.sender == address(this) ||

                msg.sender == strategist ||

                msg.sender == governance,

            "!keepers"

        );

        _;

    }



    // **** Views **** //



    function getName() external override pure returns (string memory) {

        return "StrategyCmpdDaiV2";

    }



    function getSuppliedView() public view returns (uint256) {

        (, uint256 cTokenBal, , uint256 exchangeRate) = ICToken(cdai)

            .getAccountSnapshot(address(this));



        (, uint256 bal) = mulScalarTruncate(

            Exp({mantissa: exchangeRate}),

            cTokenBal

        );



        return bal;

    }



    function getBorrowedView() public view returns (uint256) {

        return ICToken(cdai).borrowBalanceStored(address(this));

    }



    function balanceOfPool() public override view returns (uint256) {

        uint256 supplied = getSuppliedView();

        uint256 borrowed = getBorrowedView();

        return supplied.sub(borrowed);

    }



    // Given an unleveraged supply balance, return the target

    // leveraged supply balance which is still within the safety buffer

    function getLeveragedSupplyTarget(uint256 supplyBalance)

        public

        view

        returns (uint256)

    {

        uint256 leverage = getMaxLeverage();

        return supplyBalance.mul(leverage).div(1e18);

    }



    function getSafeLeverageColFactor() public view returns (uint256) {

        uint256 colFactor = getMarketColFactor();



        // Collateral factor within the buffer

        uint256 safeColFactor = colFactor.sub(

            colFactorLeverageBuffer.mul(1e18).div(colFactorLeverageBufferMax)

        );



        return safeColFactor;

    }



    function getSafeSyncColFactor() public view returns (uint256) {

        uint256 colFactor = getMarketColFactor();



        // Collateral factor within the buffer

        uint256 safeColFactor = colFactor.sub(

            colFactorSyncBuffer.mul(1e18).div(colFactorSyncBufferMax)

        );



        return safeColFactor;

    }



    function getMarketColFactor() public view returns (uint256) {

        (, uint256 colFactor) = IComptroller(comptroller).markets(cdai);



        return colFactor;

    }



    // Max leverage we can go up to, w.r.t safe buffer

    function getMaxLeverage() public view returns (uint256) {

        uint256 safeLeverageColFactor = getSafeLeverageColFactor();



        // Infinite geometric series

        uint256 leverage = uint256(1e36).div(1e18 - safeLeverageColFactor);

        return leverage;

    }



    // **** Pseudo-view functions (use `callStatic` on these) **** //

    /* The reason why these exists is because of the nature of the

       interest accruing supply + borrow balance. The "view" methods

       are technically snapshots and don't represent the real value.

       As such there are pseudo view methods where you can retrieve the

       results by calling `callStatic`.

    */



    function getCompAccrued() public returns (uint256) {

        (, , , uint256 accrued) = ICompoundLens(lens).getCompBalanceMetadataExt(

            comp,

            comptroller,

            address(this)

        );



        return accrued;

    }



    function getColFactor() public returns (uint256) {

        uint256 supplied = getSupplied();

        uint256 borrowed = getBorrowed();



        return borrowed.mul(1e18).div(supplied);

    }



    function getSuppliedUnleveraged() public returns (uint256) {

        uint256 supplied = getSupplied();

        uint256 borrowed = getBorrowed();



        return supplied.sub(borrowed);

    }



    function getSupplied() public returns (uint256) {

        return ICToken(cdai).balanceOfUnderlying(address(this));

    }



    function getBorrowed() public returns (uint256) {

        return ICToken(cdai).borrowBalanceCurrent(address(this));

    }



    function getBorrowable() public returns (uint256) {

        uint256 supplied = getSupplied();

        uint256 borrowed = getBorrowed();



        (, uint256 colFactor) = IComptroller(comptroller).markets(cdai);



        // 99.99% just in case some dust accumulates

        return

            supplied.mul(colFactor).div(1e18).sub(borrowed).mul(9999).div(

                10000

            );

    }



    function getCurrentLeverage() public returns (uint256) {

        uint256 supplied = getSupplied();

        uint256 borrowed = getBorrowed();



        return supplied.mul(1e18).div(supplied.sub(borrowed));

    }



    // **** Setters **** //



    function addKeeper(address _keeper) public {

        require(

            msg.sender == governance || msg.sender == strategist,

            "!governance"

        );

        keepers[_keeper] = true;

    }



    function removeKeeper(address _keeper) public {

        require(

            msg.sender == governance || msg.sender == strategist,

            "!governance"

        );

        keepers[_keeper] = false;

    }



    function setColFactorLeverageBuffer(uint256 _colFactorLeverageBuffer)

        public

    {

        require(

            msg.sender == governance || msg.sender == strategist,

            "!governance"

        );

        colFactorLeverageBuffer = _colFactorLeverageBuffer;

    }



    function setColFactorSyncBuffer(uint256 _colFactorSyncBuffer) public {

        require(

            msg.sender == governance || msg.sender == strategist,

            "!governance"

        );

        colFactorSyncBuffer = _colFactorSyncBuffer;

    }



    // **** State mutations **** //



    // Do a `callStatic` on this.

    // If it returns true then run it for realz. (i.e. eth_signedTx, not eth_call)

    function sync() public returns (bool) {

        uint256 colFactor = getColFactor();

        uint256 safeSyncColFactor = getSafeSyncColFactor();



        // If we're not safe

        if (colFactor > safeSyncColFactor) {

            uint256 unleveragedSupply = getSuppliedUnleveraged();

            uint256 idealSupply = getLeveragedSupplyTarget(unleveragedSupply);



            deleverageUntil(idealSupply);



            return true;

        }



        return false;

    }



    function leverageToMax() public {

        uint256 unleveragedSupply = getSuppliedUnleveraged();

        uint256 idealSupply = getLeveragedSupplyTarget(unleveragedSupply);

        leverageUntil(idealSupply);

    }



    // Leverages until we're supplying <x> amount

    // 1. Redeem <x> DAI

    // 2. Repay <x> DAI

    function leverageUntil(uint256 _supplyAmount) public onlyKeepers {

        // 1. Borrow out <X> DAI

        // 2. Supply <X> DAI



        uint256 leverage = getMaxLeverage();

        uint256 unleveragedSupply = getSuppliedUnleveraged();

        require(

            _supplyAmount >= unleveragedSupply &&

                _supplyAmount <= unleveragedSupply.mul(leverage).div(1e18),

            "!leverage"

        );



        // Since we're only leveraging one asset

        // Supplied = borrowed

        uint256 _borrowAndSupply;

        uint256 supplied = getSupplied();

        while (supplied < _supplyAmount) {

            _borrowAndSupply = getBorrowable();



            if (supplied.add(_borrowAndSupply) > _supplyAmount) {

                _borrowAndSupply = _supplyAmount.sub(supplied);

            }



            ICToken(cdai).borrow(_borrowAndSupply);

            deposit();



            supplied = supplied.add(_borrowAndSupply);

        }

    }



    function deleverageToMin() public {

        uint256 unleveragedSupply = getSuppliedUnleveraged();

        deleverageUntil(unleveragedSupply);

    }



    // Deleverages until we're supplying <x> amount

    // 1. Redeem <x> DAI

    // 2. Repay <x> DAI

    function deleverageUntil(uint256 _supplyAmount) public onlyKeepers {

        uint256 unleveragedSupply = getSuppliedUnleveraged();

        uint256 supplied = getSupplied();

        require(

            _supplyAmount >= unleveragedSupply && _supplyAmount <= supplied,

            "!deleverage"

        );



        // Since we're only leveraging on 1 asset

        // redeemable = borrowable

        uint256 _redeemAndRepay = getBorrowable();

        do {

            if (supplied.sub(_redeemAndRepay) < _supplyAmount) {

                _redeemAndRepay = supplied.sub(_supplyAmount);

            }



            require(

                ICToken(cdai).redeemUnderlying(_redeemAndRepay) == 0,

                "!redeem"

            );

            IERC20(dai).safeApprove(cdai, 0);

            IERC20(dai).safeApprove(cdai, _redeemAndRepay);

            require(ICToken(cdai).repayBorrow(_redeemAndRepay) == 0, "!repay");



            supplied = supplied.sub(_redeemAndRepay);

        } while (supplied > _supplyAmount);

    }



    function harvest() public override onlyBenevolent {

        address[] memory ctokens = new address[](1);

        ctokens[0] = cdai;



        IComptroller(comptroller).claimComp(address(this), ctokens);

        uint256 _comp = IERC20(comp).balanceOf(address(this));

        if (_comp > 0) {

            _swapUniswap(comp, want, _comp);

        }



        _distributePerformanceFeesAndDeposit();

    }



    function deposit() public override {

        uint256 _want = IERC20(want).balanceOf(address(this));

        if (_want > 0) {

            IERC20(want).safeApprove(cdai, 0);

            IERC20(want).safeApprove(cdai, _want);

            require(ICToken(cdai).mint(_want) == 0, "!deposit");

        }

    }



    function _withdrawSome(uint256 _amount)

        internal

        override

        returns (uint256)

    {

        uint256 _want = balanceOfWant();

        if (_want < _amount) {

            uint256 _redeem = _amount.sub(_want);



            // Make sure market can cover liquidity

            require(ICToken(cdai).getCash() >= _redeem, "!cash-liquidity");



            // How much borrowed amount do we need to free?

            uint256 borrowed = getBorrowed();

            uint256 supplied = getSupplied();

            uint256 curLeverage = getCurrentLeverage();

            uint256 borrowedToBeFree = _redeem.mul(curLeverage).div(1e18);



            // If the amount we need to free is > borrowed

            // Just free up all the borrowed amount

            if (borrowedToBeFree > borrowed) {

                this.deleverageToMin();

            } else {

                // Otherwise just keep freeing up borrowed amounts until

                // we hit a safe number to redeem our underlying

                this.deleverageUntil(supplied.sub(borrowedToBeFree));

            }



            // Redeems underlying

            require(ICToken(cdai).redeemUnderlying(_redeem) == 0, "!redeem");

        }



        return _amount;

    }

}

contract StrategyCurve3CRVv2 is StrategyCurveBase {

    // Curve stuff

    address public three_pool = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;

    address public three_gauge = 0xbFcF63294aD7105dEa65aA58F8AE5BE2D9d0952A;

    address public three_crv = 0x6c3F90f043a72FA612cbac8115EE7e52BDe6E490;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyCurveBase(

            three_pool,

            three_gauge,

            three_crv,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getMostPremium()

        public

        override

        view

        returns (address, uint256)

    {

        uint256[] memory balances = new uint256[](3);

        balances[0] = ICurveFi_3(curve).balances(0); // DAI

        balances[1] = ICurveFi_3(curve).balances(1).mul(10**12); // USDC

        balances[2] = ICurveFi_3(curve).balances(2).mul(10**12); // USDT



        // DAI

        if (

            balances[0] < balances[1] &&

            balances[0] < balances[2]

        ) {

            return (dai, 0);

        }



        // USDC

        if (

            balances[1] < balances[0] &&

            balances[1] < balances[2]

        ) {

            return (usdc, 1);

        }



        // USDT

        if (

            balances[2] < balances[0] &&

            balances[2] < balances[1]

        ) {

            return (usdt, 2);

        }



        // If they're somehow equal, we just want DAI

        return (dai, 0);

    }



    function getName() external override pure returns (string memory) {

        return "StrategyCurve3CRVv2";

    }



    // **** State Mutations ****



    function harvest() public onlyBenevolent override {

        // Anyone can harvest it at any given time.

        // I understand the possibility of being frontrun

        // But ETH is a dark forest, and I wanna see how this plays out

        // i.e. will be be heavily frontrunned?

        //      if so, a new strategy will be deployed.



        // stablecoin we want to convert to

        (address to, uint256 toIndex) = getMostPremium();



        // Collects crv tokens

        // Don't bother voting in v1

        ICurveMintr(mintr).mint(gauge);

        uint256 _crv = IERC20(crv).balanceOf(address(this));

        if (_crv > 0) {

            // x% is sent back to the rewards holder

            // to be used to lock up in as veCRV in a future date

            uint256 _keepCRV = _crv.mul(keepCRV).div(keepCRVMax);

            if (_keepCRV > 0) {

                IERC20(crv).safeTransfer(

                    IController(controller).treasury(),

                    _keepCRV

                );

            }

            _crv = _crv.sub(_keepCRV);

            _swapUniswap(crv, to, _crv);

        }



        // Adds liquidity to curve.fi's pool

        // to get back want (scrv)

        uint256 _to = IERC20(to).balanceOf(address(this));

        if (_to > 0) {

            IERC20(to).safeApprove(curve, 0);

            IERC20(to).safeApprove(curve, _to);

            uint256[3] memory liquidity;

            liquidity[toIndex] = _to;

            ICurveFi_3(curve).add_liquidity(liquidity, 0);

        }



        _distributePerformanceFeesAndDeposit();

    }

}

contract StrategyCurveRenCRVv2 is StrategyCurveBase {

    // https://www.curve.fi/ren

    // Curve stuff

    address public ren_pool = 0x93054188d876f558f4a66B2EF1d97d16eDf0895B;

    address public ren_gauge = 0xB1F2cdeC61db658F091671F5f199635aEF202CAC;

    address public ren_crv = 0x49849C98ae39Fff122806C06791Fa73784FB3675;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyCurveBase(

            ren_pool,

            ren_gauge,

            ren_crv,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getMostPremium() public override view returns (address, uint256) {

        // Both 8 decimals, so doesn't matter

        uint256[] memory balances = new uint256[](3);

        balances[0] = ICurveFi_2(curve).balances(0); // RENBTC

        balances[1] = ICurveFi_2(curve).balances(1); // WBTC



        // renbtc

        if (balances[0] < balances[1]) {

            return (renbtc, 0);

        }



        // WBTC

        if (balances[1] < balances[0]) {

            return (wbtc, 1);

        }



        // If they're somehow equal, we just want RENBTC

        return (renbtc, 0);

    }



    function getName() external override pure returns (string memory) {

        return "StrategyCurveRenCRVv2";

    }



    // **** State Mutations ****



    function harvest() public override onlyBenevolent {

        // Anyone can harvest it at any given time.

        // I understand the possibility of being frontrun

        // But ETH is a dark forest, and I wanna see how this plays out

        // i.e. will be be heavily frontrunned?

        //      if so, a new strategy will be deployed.



        // stablecoin we want to convert to

        (address to, uint256 toIndex) = getMostPremium();



        // Collects crv tokens

        // Don't bother voting in v1

        ICurveMintr(mintr).mint(gauge);

        uint256 _crv = IERC20(crv).balanceOf(address(this));

        if (_crv > 0) {

            // x% is sent back to the rewards holder

            // to be used to lock up in as veCRV in a future date

            uint256 _keepCRV = _crv.mul(keepCRV).div(keepCRVMax);

            if (_keepCRV > 0) {

                IERC20(crv).safeTransfer(

                    IController(controller).treasury(),

                    _keepCRV

                );

            }

            _crv = _crv.sub(_keepCRV);

            _swapUniswap(crv, to, _crv);

        }



        // Adds liquidity to curve.fi's pool

        // to get back want (scrv)

        uint256 _to = IERC20(to).balanceOf(address(this));

        if (_to > 0) {

            IERC20(to).safeApprove(curve, 0);

            IERC20(to).safeApprove(curve, _to);

            uint256[2] memory liquidity;

            liquidity[toIndex] = _to;

            ICurveFi_2(curve).add_liquidity(liquidity, 0);

        }



        _distributePerformanceFeesAndDeposit();

    }

}

contract StrategyCurveSCRVv3_2 is StrategyCurveBase {

    // Curve stuff

    address public susdv2_pool = 0xA5407eAE9Ba41422680e2e00537571bcC53efBfD;

    address public susdv2_gauge = 0xA90996896660DEcC6E997655E065b23788857849;

    address public scrv = 0xC25a3A3b969415c80451098fa907EC722572917F;



    // Harvesting

    address public snx = 0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F;



    constructor(

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyCurveBase(

            susdv2_pool,

            susdv2_gauge,

            scrv,

            _governance,

            _strategist,

            _controller,

            _timelock

        )

    {}



    // **** Views ****



    function getMostPremium()

        public

        override

        view

        returns (address, uint256)

    {

        uint256[] memory balances = new uint256[](4);

        balances[0] = ICurveFi_4(curve).balances(0); // DAI

        balances[1] = ICurveFi_4(curve).balances(1).mul(10**12); // USDC

        balances[2] = ICurveFi_4(curve).balances(2).mul(10**12); // USDT

        balances[3] = ICurveFi_4(curve).balances(3); // sUSD



        // DAI

        if (

            balances[0] < balances[1] &&

            balances[0] < balances[2] &&

            balances[0] < balances[3]

        ) {

            return (dai, 0);

        }



        // USDC

        if (

            balances[1] < balances[0] &&

            balances[1] < balances[2] &&

            balances[1] < balances[3]

        ) {

            return (usdc, 1);

        }



        // USDT

        if (

            balances[2] < balances[0] &&

            balances[2] < balances[1] &&

            balances[2] < balances[3]

        ) {

            return (usdt, 2);

        }



        // SUSD

        if (

            balances[3] < balances[0] &&

            balances[3] < balances[1] &&

            balances[3] < balances[2]

        ) {

            return (susd, 3);

        }



        // If they're somehow equal, we just want DAI

        return (dai, 0);

    }



    function getName() external override pure returns (string memory) {

        return "StrategyCurveSCRVv3_2";

    }



    // **** State Mutations ****



    function harvest() public onlyBenevolent override {

        // Anyone can harvest it at any given time.

        // I understand the possibility of being frontrun

        // But ETH is a dark forest, and I wanna see how this plays out

        // i.e. will be be heavily frontrunned?

        //      if so, a new strategy will be deployed.



        // stablecoin we want to convert to

        (address to, uint256 toIndex) = getMostPremium();



        // Collects crv tokens

        // Don't bother voting in v1

        ICurveMintr(mintr).mint(gauge);

        uint256 _crv = IERC20(crv).balanceOf(address(this));

        if (_crv > 0) {

            // x% is sent back to the rewards holder

            // to be used to lock up in as veCRV in a future date

            uint256 _keepCRV = _crv.mul(keepCRV).div(keepCRVMax);

            if (_keepCRV > 0) {

                IERC20(crv).safeTransfer(

                    IController(controller).treasury(),

                    _keepCRV

                );

            }

            _crv = _crv.sub(_keepCRV);

            _swapUniswap(crv, to, _crv);

        }



        // Collects SNX tokens

        ICurveGauge(gauge).claim_rewards(address(this));

        uint256 _snx = IERC20(snx).balanceOf(address(this));

        if (_snx > 0) {

            _swapUniswap(snx, to, _snx);

        }



        // Adds liquidity to curve.fi's susd pool

        // to get back want (scrv)

        uint256 _to = IERC20(to).balanceOf(address(this));

        if (_to > 0) {

            IERC20(to).safeApprove(curve, 0);

            IERC20(to).safeApprove(curve, _to);

            uint256[4] memory liquidity;

            liquidity[toIndex] = _to;

            ICurveFi_4(curve).add_liquidity(liquidity, 0);

        }



        // We want to get back sCRV

        _distributePerformanceFeesAndDeposit();

    }

}

contract StrategyCurveSCRVv4_1 is StrategyBase {

    // Curve

    address public scrv = 0xC25a3A3b969415c80451098fa907EC722572917F;

    address public susdv2_gauge = 0xA90996896660DEcC6E997655E065b23788857849;

    address public susdv2_pool = 0xA5407eAE9Ba41422680e2e00537571bcC53efBfD;

    address public escrow = 0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2;



    // curve dao

    address public gauge;

    address public curve;

    address public mintr = 0xd061D61a4d941c39E5453435B6345Dc261C2fcE0;



    // tokens we're farming

    address public constant crv = 0xD533a949740bb3306d119CC777fa900bA034cd52;

    address public constant snx = 0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F;



    // stablecoins

    address public dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    address public usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    address public usdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    address public susd = 0x57Ab1ec28D129707052df4dF418D58a2D46d5f51;



    // How much CRV tokens to keep

    uint256 public keepCRV = 500;

    uint256 public keepCRVMax = 10000;



    // crv-locker and voter

    address public scrvVoter;

    address public crvLocker;



    constructor(

        address _scrvVoter,

        address _crvLocker,

        address _governance,

        address _strategist,

        address _controller,

        address _timelock

    )

        public

        StrategyBase(scrv, _governance, _strategist, _controller, _timelock)

    {

        curve = susdv2_pool;

        gauge = susdv2_gauge;



        scrvVoter = _scrvVoter;

        crvLocker = _crvLocker;

    }



    // **** Getters ****



    function balanceOfPool() public override view returns (uint256) {

        return SCRVVoter(scrvVoter).balanceOf(gauge);

    }



    function getName() external override pure returns (string memory) {

        return "StrategyCurveSCRVv4_1";

    }



    function getHarvestable() external returns (uint256) {

        return ICurveGauge(gauge).claimable_tokens(crvLocker);

    }



    function getMostPremium() public view returns (address, uint8) {

        uint256[] memory balances = new uint256[](4);

        balances[0] = ICurveFi_4(curve).balances(0); // DAI

        balances[1] = ICurveFi_4(curve).balances(1).mul(10**12); // USDC

        balances[2] = ICurveFi_4(curve).balances(2).mul(10**12); // USDT

        balances[3] = ICurveFi_4(curve).balances(3); // sUSD



        // DAI

        if (

            balances[0] < balances[1] &&

            balances[0] < balances[2] &&

            balances[0] < balances[3]

        ) {

            return (dai, 0);

        }



        // USDC

        if (

            balances[1] < balances[0] &&

            balances[1] < balances[2] &&

            balances[1] < balances[3]

        ) {

            return (usdc, 1);

        }



        // USDT

        if (

            balances[2] < balances[0] &&

            balances[2] < balances[1] &&

            balances[2] < balances[3]

        ) {

            return (usdt, 2);

        }



        // SUSD

        if (

            balances[3] < balances[0] &&

            balances[3] < balances[1] &&

            balances[3] < balances[2]

        ) {

            return (susd, 3);

        }



        // If they're somehow equal, we just want DAI

        return (dai, 0);

    }



    // **** Setters ****



    function setKeepCRV(uint256 _keepCRV) external {

        require(msg.sender == governance, "!governance");

        keepCRV = _keepCRV;

    }



    // **** State Mutations ****



    function deposit() public override {

        uint256 _want = IERC20(want).balanceOf(address(this));

        if (_want > 0) {

            IERC20(want).safeTransfer(scrvVoter, _want);

            SCRVVoter(scrvVoter).deposit(gauge, want);

        }

    }



    function _withdrawSome(uint256 _amount)

        internal

        override

        returns (uint256)

    {

        return SCRVVoter(scrvVoter).withdraw(gauge, want, _amount);

    }



    function harvest() public override onlyBenevolent {

        // Anyone can harvest it at any given time.

        // I understand the possibility of being frontrun / sandwiched

        // But ETH is a dark forest, and I wanna see how this plays out

        // i.e. will be be heavily frontrunned/sandwiched?

        //      if so, a new strategy will be deployed.



        // stablecoin we want to convert to

        (address to, uint256 toIndex) = getMostPremium();



        // Collects crv tokens

        // Don't bother voting in v1

        SCRVVoter(scrvVoter).harvest(gauge);

        uint256 _crv = IERC20(crv).balanceOf(address(this));

        if (_crv > 0) {

            // How much CRV to keep to restake?

            uint256 _keepCRV = _crv.mul(keepCRV).div(keepCRVMax);

            IERC20(crv).safeTransfer(address(crvLocker), _keepCRV);



            // How much CRV to swap?

            _crv = _crv.sub(_keepCRV);

            _swapUniswap(crv, to, _crv);

        }



        // Collects SNX tokens

        SCRVVoter(scrvVoter).claimRewards();

        uint256 _snx = IERC20(snx).balanceOf(address(this));

        if (_snx > 0) {

            _swapUniswap(snx, to, _snx);

        }



        // Adds liquidity to curve.fi's susd pool

        // to get back want (scrv)

        uint256 _to = IERC20(to).balanceOf(address(this));

        if (_to > 0) {

            IERC20(to).safeApprove(curve, 0);

            IERC20(to).safeApprove(curve, _to);

            uint256[4] memory liquidity;

            liquidity[toIndex] = _to;

            ICurveFi_4(curve).add_liquidity(liquidity, 0);

        }



        // We want to get back sCRV

        _distributePerformanceFeesAndDeposit();

    }

}

contract DSTestApprox is DSTest {

    function assertEqApprox(uint256 a, uint256 b) internal {

        if (a == 0 && b == 0) {

            return;

        }



        // +/- 5%

        uint256 bMax = (b * 105) / 100;

        uint256 bMin = (b * 95) / 100;



        if (!(a > bMin && a < bMax)) {

            emit log_bytes32("Error: Wrong `a-uint` value!");

            emit log_named_uint("  Expected", b);

            emit log_named_uint("    Actual", a);

            fail();

        }

    }



    function assertEqVerbose(bool a, bytes memory b) internal {

        if (!a) {

            emit log_bytes32("Error: assertion error!");

            emit logs(b);

            fail();

        }

    }

}

contract DSTestDefiBase is DSTestApprox {

    using SafeERC20 for IERC20;

    using SafeMath for uint256;



    address pickle = 0x429881672B9AE42b8EbA0E26cD9C73711b891Ca5;

    address burn = 0x000000000000000000000000000000000000dEaD;



    address susdv2_deposit = 0xFCBa3E75865d2d561BE8D220616520c171F12851;



    address susdv2_pool = 0xA5407eAE9Ba41422680e2e00537571bcC53efBfD;

    address three_pool = 0xbEbc44782C7dB0a1A60Cb6fe97d0b483032FF1C7;

    address ren_pool = 0x93054188d876f558f4a66B2EF1d97d16eDf0895B;



    address scrv = 0xC25a3A3b969415c80451098fa907EC722572917F;

    address three_crv = 0x6c3F90f043a72FA612cbac8115EE7e52BDe6E490;

    address ren_crv = 0x49849C98ae39Fff122806C06791Fa73784FB3675;



    address eth = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;

    address weth = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;

    address crv = 0xD533a949740bb3306d119CC777fa900bA034cd52;

    address snx = 0xC011a73ee8576Fb46F5E1c5751cA3B9Fe0af2a6F;

    address dai = 0x6B175474E89094C44Da98b954EedeAC495271d0F;

    address usdc = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;

    address usdt = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    address susd = 0x57Ab1ec28D129707052df4dF418D58a2D46d5f51;

    address uni = 0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984;



    address wbtc = 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599;

    address renbtc = 0xEB4C2781e4ebA804CE9a9803C67d0893436bB27D;



    Hevm hevm = Hevm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);



    UniswapRouterV2 univ2 = UniswapRouterV2(

        0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D

    );



    IUniswapV2Factory univ2Factory = IUniswapV2Factory(

        0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f

    );



    ICurveFi_4 curveSusdV2 = ICurveFi_4(

        0xA5407eAE9Ba41422680e2e00537571bcC53efBfD

    );



    uint256 startTime = block.timestamp;



    receive() external payable {}

    fallback () external payable {}



    function _swap(

        address _from,

        address _to,

        uint256 _amount

    ) internal {

        address[] memory path;



        if (_from == eth || _from == weth) {

            path = new address[](2);

            path[0] = weth;

            path[1] = _to;



            univ2.swapExactETHForTokens{value: _amount}(

                0,

                path,

                address(this),

                now + 60

            );

        } else {

            path = new address[](3);

            path[0] = _from;

            path[1] = weth;

            path[2] = _to;



            IERC20(_from).safeApprove(address(univ2), 0);

            IERC20(_from).safeApprove(address(univ2), _amount);



            univ2.swapExactTokensForTokens(

                _amount,

                0,

                path,

                address(this),

                now + 60

            );

        }

    }



    function _getERC20(address token, uint256 _amount) internal {

        address[] memory path = new address[](2);

        path[0] = weth;

        path[1] = token;



        uint256[] memory ins = univ2.getAmountsIn(_amount, path);

        uint256 ethAmount = ins[0];



        univ2.swapETHForExactTokens{value: ethAmount}(

            _amount,

            path,

            address(this),

            now + 60

        );

    }



    function _getERC20WithETH(address token, uint256 _ethAmount) internal {

        address[] memory path = new address[](2);

        path[0] = weth;

        path[1] = token;



        univ2.swapExactETHForTokens{value: _ethAmount}(

            0,

            path,

            address(this),

            now + 60

        );

    }



    function _getUniV2LPToken(address lpToken, uint256 _ethAmount) internal {

        address token0 = IUniswapV2Pair(lpToken).token0();

        address token1 = IUniswapV2Pair(lpToken).token1();



        if (token0 != weth) {

            _getERC20WithETH(token0, _ethAmount.div(2));

        } else {

            WETH(weth).deposit{value: _ethAmount.div(2)}();

        }



        if (token1 != weth) {

            _getERC20WithETH(token1, _ethAmount.div(2));

        } else {

            WETH(weth).deposit{value: _ethAmount.div(2)}();

        }



        IERC20(token0).safeApprove(address(univ2), uint256(0));

        IERC20(token0).safeApprove(address(univ2), uint256(-1));



        IERC20(token1).safeApprove(address(univ2), uint256(0));

        IERC20(token1).safeApprove(address(univ2), uint256(-1));

        univ2.addLiquidity(

            token0,

            token1,

            IERC20(token0).balanceOf(address(this)),

            IERC20(token1).balanceOf(address(this)),

            0,

            0,

            address(this),

            now + 60

        );

    }



    function _getUniV2LPToken(

        address token0,

        address token1,

        uint256 _ethAmount

    ) internal {

        _getUniV2LPToken(univ2Factory.getPair(token0, token1), _ethAmount);

    }



    function _getFunctionSig(string memory sig) internal pure returns (bytes4) {

        return bytes4(keccak256(bytes(sig)));

    }



    function _getDynamicArray(address payable one)

        internal

        pure

        returns (address payable[] memory)

    {

        address payable[] memory targets = new address payable[](1);

        targets[0] = one;



        return targets;

    }



    function _getDynamicArray(bytes memory one)

        internal

        pure

        returns (bytes[] memory)

    {

        bytes[] memory data = new bytes[](1);

        data[0] = one;



        return data;

    }



    function _getDynamicArray(address payable one, address payable two)

        internal

        pure

        returns (address payable[] memory)

    {

        address payable[] memory targets = new address payable[](2);

        targets[0] = one;

        targets[1] = two;



        return targets;

    }



    function _getDynamicArray(bytes memory one, bytes memory two)

        internal

        pure

        returns (bytes[] memory)

    {

        bytes[] memory data = new bytes[](2);

        data[0] = one;

        data[1] = two;



        return data;

    }



    function _getDynamicArray(

        address payable one,

        address payable two,

        address payable three

    ) internal pure returns (address payable[] memory) {

        address payable[] memory targets = new address payable[](3);

        targets[0] = one;

        targets[1] = two;

        targets[2] = three;



        return targets;

    }



    function _getDynamicArray(

        bytes memory one,

        bytes memory two,

        bytes memory three

    ) internal pure returns (bytes[] memory) {

        bytes[] memory data = new bytes[](3);

        data[0] = one;

        data[1] = two;

        data[2] = three;



        return data;

    }

}

contract StrategyCurveFarmTestBase is DSTestDefiBase {

    address governance;

    address strategist;

    address timelock;



    address devfund;

    address treasury;



    address want;



    PickleJar pickleJar;

    ControllerV4 controller;

    IStrategy strategy;



    // **** Tests ****



    function _test_withdraw() internal {

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);



        // Deposits to strategy

        pickleJar.earn();



        // Fast forwards

        hevm.warp(block.timestamp + 1 weeks);



        strategy.harvest();



        // Withdraws back to pickleJar

        uint256 _before = IERC20(want).balanceOf(address(pickleJar));

        controller.withdrawAll(want);

        uint256 _after = IERC20(want).balanceOf(address(pickleJar));



        assertTrue(_after > _before);



        _before = IERC20(want).balanceOf(address(this));

        pickleJar.withdrawAll();

        _after = IERC20(want).balanceOf(address(this));



        assertTrue(_after > _before);



        // Gained some interest

        assertTrue(_after > _want);

    }



    function _test_get_earn_harvest_rewards() internal {

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        // Fast forward one week

        hevm.warp(block.timestamp + 1 weeks);



        // Call the harvest function

        uint256 _before = pickleJar.balance();

        uint256 _treasuryBefore = IERC20(want).balanceOf(treasury);

        strategy.harvest();

        uint256 _after = pickleJar.balance();

        uint256 _treasuryAfter = IERC20(want).balanceOf(treasury);



        uint256 earned = _after.sub(_before).mul(1000).div(955);

        uint256 earnedRewards = earned.mul(45).div(1000); // 4.5%

        uint256 actualRewardsEarned = _treasuryAfter.sub(_treasuryBefore);



        // 4.5% performance fee is given

        assertEqApprox(earnedRewards, actualRewardsEarned);



        // Withdraw

        uint256 _devBefore = IERC20(want).balanceOf(devfund);

        _treasuryBefore = IERC20(want).balanceOf(treasury);

        uint256 _stratBal = strategy.balanceOf();

        pickleJar.withdrawAll();

        uint256 _devAfter = IERC20(want).balanceOf(devfund);

        _treasuryAfter = IERC20(want).balanceOf(treasury);



        // 0.175% goes to dev

        uint256 _devFund = _devAfter.sub(_devBefore);

        assertEq(_devFund, _stratBal.mul(175).div(100000));



        // 0.325% goes to treasury

        uint256 _treasuryFund = _treasuryAfter.sub(_treasuryBefore);

        assertEq(_treasuryFund, _stratBal.mul(325).div(100000));

    }

}

contract StrategyUniFarmTestBase is DSTestDefiBase {

    address want;

    address token1;



    address governance;

    address strategist;

    address timelock;



    address devfund;

    address treasury;



    PickleJar pickleJar;

    ControllerV4 controller;

    IStrategy strategy;



    function _getWant(uint256 ethAmount, uint256 amount) internal {

        _getERC20(token1, amount);



        uint256 _token1 = IERC20(token1).balanceOf(address(this));



        IERC20(token1).safeApprove(address(univ2), 0);

        IERC20(token1).safeApprove(address(univ2), _token1);



        univ2.addLiquidityETH{value: ethAmount}(

            token1,

            _token1,

            0,

            0,

            address(this),

            now + 60

        );

    }



    // **** Tests ****



    function _test_timelock() internal {

        assertTrue(strategy.timelock() == timelock);

        strategy.setTimelock(address(1));

        assertTrue(strategy.timelock() == address(1));

    }



    function _test_withdraw_release() internal {

        uint256 decimals = ERC20(token1).decimals();

        _getWant(10 ether, 4000 * (10**decimals));

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).safeApprove(address(pickleJar), 0);

        IERC20(want).safeApprove(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();

        hevm.warp(block.timestamp + 1 weeks);

        strategy.harvest();



        // Checking withdraw

        uint256 _before = IERC20(want).balanceOf(address(pickleJar));

        controller.withdrawAll(want);

        uint256 _after = IERC20(want).balanceOf(address(pickleJar));

        assertTrue(_after > _before);

        _before = IERC20(want).balanceOf(address(this));

        pickleJar.withdrawAll();

        _after = IERC20(want).balanceOf(address(this));

        assertTrue(_after > _before);



        // Check if we gained interest

        assertTrue(_after > _want);

    }



    function _test_get_earn_harvest_rewards() internal {

        uint256 decimals = ERC20(token1).decimals();

        _getWant(10 ether, 4000 * (10**decimals));

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).safeApprove(address(pickleJar), 0);

        IERC20(want).safeApprove(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();

        hevm.warp(block.timestamp + 1 weeks);



        // Call the harvest function

        uint256 _before = pickleJar.balance();

        uint256 _treasuryBefore = IERC20(want).balanceOf(treasury);

        strategy.harvest();

        uint256 _after = pickleJar.balance();

        uint256 _treasuryAfter = IERC20(want).balanceOf(treasury);



        uint256 earned = _after.sub(_before).mul(1000).div(955);

        uint256 earnedRewards = earned.mul(45).div(1000); // 4.5%

        uint256 actualRewardsEarned = _treasuryAfter.sub(_treasuryBefore);



        // 4.5% performance fee is given

        assertEqApprox(earnedRewards, actualRewardsEarned);



        // Withdraw

        uint256 _devBefore = IERC20(want).balanceOf(devfund);

        _treasuryBefore = IERC20(want).balanceOf(treasury);

        uint256 _stratBal = strategy.balanceOf();

        pickleJar.withdrawAll();

        uint256 _devAfter = IERC20(want).balanceOf(devfund);

        _treasuryAfter = IERC20(want).balanceOf(treasury);



        // 0.175% goes to dev

        uint256 _devFund = _devAfter.sub(_devBefore);

        assertEq(_devFund, _stratBal.mul(175).div(100000));



        // 0.325% goes to treasury

        uint256 _treasuryFund = _treasuryAfter.sub(_treasuryBefore);

        assertEq(_treasuryFund, _stratBal.mul(325).div(100000));

    }

}

contract PickleSwapTest is DSTestDefiBase {

    PickleSwap pickleSwap;



    function setUp() public {

        pickleSwap = new PickleSwap();

    }



    function _test_uni_lp_swap(address lp1, address lp2) internal {

        _getUniV2LPToken(lp1, 20 ether);

        uint256 _balance = IERC20(lp1).balanceOf(address(this));



        uint256 _before = IERC20(lp2).balanceOf(address(this));

        IERC20(lp1).safeIncreaseAllowance(address(pickleSwap), _balance);

        pickleSwap.convertWETHPair(lp1, lp2, _balance);

        uint256 _after = IERC20(lp2).balanceOf(address(this));



        assertTrue(_after > _before);

        assertTrue(_after > 0);

    }



    function test_pickleswap_dai_usdc() public {

        _test_uni_lp_swap(

            univ2Factory.getPair(weth, dai),

            univ2Factory.getPair(weth, usdc)

        );

    }



    function test_pickleswap_dai_usdt() public {

        _test_uni_lp_swap(

            univ2Factory.getPair(weth, dai),

            univ2Factory.getPair(weth, usdt)

        );

    }



    function test_pickleswap_usdt_susd() public {

        _test_uni_lp_swap(

            univ2Factory.getPair(weth, usdt),

            univ2Factory.getPair(weth, susd)

        );

    }

}

contract StrategyCmpndDaiV1 is DSTestDefiBase {

    StrategyCmpdDaiV2 strategy;

    ControllerV4 controller;

    PickleJar pickleJar;



    address governance;

    address strategist;

    address timelock;

    address devfund;

    address treasury;



    address want;



    function setUp() public {

        want = dai;



        governance = address(this);

        strategist = address(new User());

        timelock = address(this);

        devfund = address(new User());

        treasury = address(new User());



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = new StrategyCmpdDaiV2(

            governance,

            strategist,

            address(controller),

            timelock

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));

    }



    function testFail_cmpnd_dai_v1_onlyKeeper_leverage() public {

        _getERC20(want, 100e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);



        User randomUser = new User();

        randomUser.execute(address(strategy), 0, "leverageToMax()", "");

    }



    function testFail_cmpnd_dai_v1_onlyKeeper_deleverage() public {

        _getERC20(want, 100e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        strategy.leverageToMax();



        User randomUser = new User();

        randomUser.execute(address(strategy), 0, "deleverageToMin()", "");

    }



    function test_cmpnd_dai_v1_comp_accrued() public {

        _getERC20(want, 1000000e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        strategy.leverageToMax();



        uint256 compAccrued = strategy.getCompAccrued();



        assertEq(compAccrued, 0);



        hevm.warp(block.timestamp + 1 days);

        hevm.roll(block.number + 6171); // Roughly number of blocks per day



        compAccrued = strategy.getCompAccrued();

        assertTrue(compAccrued > 0);

    }



    function test_cmpnd_dai_v1_comp_sync() public {

        _getERC20(want, 1000000e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        // Sets colFactor Buffer to be 3% (safeSync is 5%)

        strategy.setColFactorLeverageBuffer(30);

        strategy.leverageToMax();

        // Back to 10%

        strategy.setColFactorLeverageBuffer(100);



        uint256 colFactor = strategy.getColFactor();

        uint256 safeColFactor = strategy.getSafeLeverageColFactor();

        assertTrue(colFactor > safeColFactor);



        // Sync automatically fixes the colFactor for us

        bool shouldSync = strategy.sync();

        assertTrue(shouldSync);



        colFactor = strategy.getColFactor();

        assertEqApprox(colFactor, safeColFactor);



        shouldSync = strategy.sync();

        assertTrue(!shouldSync);

    }



    function test_cmpnd_dai_v1_leverage() public {

        _getERC20(want, 100e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        uint256 _stratInitialBal = strategy.balanceOf();



        uint256 _beforeCR = strategy.getColFactor();

        uint256 _beforeLev = strategy.getCurrentLeverage();

        strategy.leverageToMax();

        uint256 _afterCR = strategy.getColFactor();

        uint256 _afterLev = strategy.getCurrentLeverage();

        uint256 _safeLeverageColFactor = strategy.getSafeLeverageColFactor();



        assertTrue(_afterCR > _beforeCR);

        assertTrue(_afterLev > _beforeLev);

        assertEqApprox(_safeLeverageColFactor, _afterCR);



        uint256 _maxLeverage = strategy.getMaxLeverage();

        assertTrue(_maxLeverage > 2e18); // Should be ~2.6, depending on colFactorLeverageBuffer



        uint256 leverageTarget = strategy.getLeveragedSupplyTarget(

            _stratInitialBal

        );

        uint256 leverageSupplied = strategy.getSupplied();

        assertEqApprox(

            leverageSupplied,

            _stratInitialBal.mul(_maxLeverage).div(1e18)

        );

        assertEqApprox(leverageSupplied, leverageTarget);



        uint256 unleveragedSupplied = strategy.getSuppliedUnleveraged();

        assertEqApprox(unleveragedSupplied, _stratInitialBal);

    }



    function test_cmpnd_dai_v1_deleverage() public {

        _getERC20(want, 100e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();

        strategy.leverageToMax();



        uint256 _beforeCR = strategy.getColFactor();

        uint256 _beforeLev = strategy.getCurrentLeverage();

        strategy.deleverageToMin();

        uint256 _afterCR = strategy.getColFactor();

        uint256 _afterLev = strategy.getCurrentLeverage();



        assertTrue(_afterCR < _beforeCR);

        assertTrue(_afterLev < _beforeLev);

        assertEq(0, _afterCR); // 0 since we're not borrowing anything



        uint256 unleveragedSupplied = strategy.getSuppliedUnleveraged();

        uint256 supplied = strategy.getSupplied();

        assertEqApprox(unleveragedSupplied, supplied);

    }



    function test_cmpnd_dai_v1_withdrawSome() public {

        _getERC20(want, 100e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();

        strategy.leverageToMax();



        uint256 _before = IERC20(want).balanceOf(address(this));

        pickleJar.withdraw(25e18);

        uint256 _after = IERC20(want).balanceOf(address(this));



        assertTrue(_after > _before);

        assertEqApprox(_after.sub(_before), 25e18);



        _before = IERC20(want).balanceOf(address(this));

        pickleJar.withdraw(10e18);

        _after = IERC20(want).balanceOf(address(this));



        assertTrue(_after > _before);

        assertEqApprox(_after.sub(_before), 10e18);



        _before = IERC20(want).balanceOf(address(this));

        pickleJar.withdraw(30e18);

        _after = IERC20(want).balanceOf(address(this));



        assertTrue(_after > _before);

        assertEqApprox(_after.sub(_before), 30e18);



        // Make sure we're still leveraging

        uint256 _leverage = strategy.getCurrentLeverage();

        assertTrue(_leverage > 1e18);

    }



    function test_cmpnd_dai_v1_withdrawAll() public {

        _getERC20(want, 100e18);



        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        strategy.leverageToMax();



        hevm.warp(block.timestamp + 1 days);

        hevm.roll(block.number + 6171); // Roughly number of blocks per day



        strategy.harvest();



        // Withdraws back to pickleJar

        uint256 _before = IERC20(want).balanceOf(address(pickleJar));

        controller.withdrawAll(want);

        uint256 _after = IERC20(want).balanceOf(address(pickleJar));



        assertTrue(_after > _before);



        _before = IERC20(want).balanceOf(address(this));

        pickleJar.withdrawAll();

        _after = IERC20(want).balanceOf(address(this));



        assertTrue(_after > _before);



        // Gained some interest

        assertTrue(_after > _want);

    }



    function test_cmpnd_dai_v1_earn_harvest_rewards() public {

        _getERC20(want, 100e18);



        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        // Fast forward one week

        hevm.warp(block.timestamp + 1 days);

        hevm.roll(block.number + 6171); // Roughly number of blocks per day



        // Call the harvest function

        uint256 _before = strategy.getSupplied();

        uint256 _treasuryBefore = IERC20(want).balanceOf(treasury);

        strategy.harvest();

        uint256 _after = strategy.getSupplied();

        uint256 _treasuryAfter = IERC20(want).balanceOf(treasury);



        uint256 earned = _after.sub(_before).mul(1000).div(955);

        uint256 earnedRewards = earned.mul(45).div(1000); // 4.5%

        uint256 actualRewardsEarned = _treasuryAfter.sub(_treasuryBefore);



        // 4.5% performance fee is given

        assertEqApprox(earnedRewards, actualRewardsEarned);



        // Withdraw

        uint256 _devBefore = IERC20(want).balanceOf(devfund);

        _treasuryBefore = IERC20(want).balanceOf(treasury);

        uint256 _stratBal = strategy.balanceOf();

        pickleJar.withdrawAll();

        uint256 _devAfter = IERC20(want).balanceOf(devfund);

        _treasuryAfter = IERC20(want).balanceOf(treasury);



        // 0.175% goes to dev

        uint256 _devFund = _devAfter.sub(_devBefore);

        assertEq(_devFund, _stratBal.mul(175).div(100000));



        // 0.325% goes to treasury

        uint256 _treasuryFund = _treasuryAfter.sub(_treasuryBefore);

        assertEq(_treasuryFund, _stratBal.mul(325).div(100000));

    }



    function test_cmpnd_dai_v1_functions() public {

        _getERC20(want, 100e18);



        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();



        uint256 initialSupplied = strategy.getSupplied();

        uint256 initialBorrowed = strategy.getBorrowed();

        uint256 initialBorrowable = strategy.getBorrowable();

        uint256 marketColFactor = strategy.getMarketColFactor();

        uint256 maxLeverage = strategy.getMaxLeverage();



        // Earn deposits 95% into strategy

        assertEqApprox(initialSupplied, 95e18);

        assertEqApprox(

            initialBorrowable,

            initialSupplied.mul(marketColFactor).div(1e18)

        );

        assertEqApprox(initialBorrowed, 0);



        // Leverage to Max

        strategy.leverageToMax();



        uint256 supplied = strategy.getSupplied();

        uint256 borrowed = strategy.getBorrowed();

        uint256 borrowable = strategy.getBorrowable();

        uint256 currentColFactor = strategy.getColFactor();

        uint256 safeLeverageColFactor = strategy.getSafeLeverageColFactor();



        assertEqApprox(supplied, initialSupplied.mul(maxLeverage).div(1e18));

        assertEqApprox(borrowed, supplied.mul(safeLeverageColFactor).div(1e18));

        assertEqApprox(

            borrowable,

            supplied.mul(marketColFactor.sub(currentColFactor)).div(1e18)

        );

        assertEqApprox(currentColFactor, safeLeverageColFactor);

        assertTrue(marketColFactor > currentColFactor);

        assertTrue(marketColFactor > safeLeverageColFactor);



        // Deleverage

        strategy.deleverageToMin();



        uint256 deleverageSupplied = strategy.getSupplied();

        uint256 deleverageBorrowed = strategy.getBorrowed();

        uint256 deleverageBorrowable = strategy.getBorrowable();



        assertEqApprox(deleverageSupplied, initialSupplied);

        assertEqApprox(deleverageBorrowed, initialBorrowed);

        assertEqApprox(deleverageBorrowable, initialBorrowable);

    }



    function test_cmpnd_dai_v1_deleverage_stepping() public {

        _getERC20(want, 100e18);

        uint256 _want = IERC20(want).balanceOf(address(this));

        IERC20(want).approve(address(pickleJar), _want);

        pickleJar.deposit(_want);

        pickleJar.earn();

        strategy.leverageToMax();



        strategy.deleverageUntil(200e18);

        uint256 supplied = strategy.getSupplied();

        assertEqApprox(supplied, 200e18);



        strategy.deleverageUntil(180e18);

        supplied = strategy.getSupplied();

        assertEqApprox(supplied, 180e18);



        strategy.deleverageUntil(120e18);

        supplied = strategy.getSupplied();

        assertEqApprox(supplied, 120e18);

    }

}

contract StrategyCurve3CRVv2Test is StrategyCurveFarmTestBase {

    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        want = three_crv;



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyCurve3CRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        hevm.warp(startTime);



        _getWant(10000000 ether);

    }



    function _getWant(uint256 daiAmount) internal {

        _getERC20(dai, daiAmount);

        uint256[3] memory liquidity;

        liquidity[0] = IERC20(dai).balanceOf(address(this));

        IERC20(dai).approve(three_pool, liquidity[0]);

        ICurveFi_3(three_pool).add_liquidity(liquidity, 0);

    }



    // **** Tests **** //



    function test_3crv_v1_withdraw() public {

        _test_withdraw();

    }



    function test_3crv_v1_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract StrategyCurveRenCRVv2Test is StrategyCurveFarmTestBase {

    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        want = ren_crv;



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyCurveRenCRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        hevm.warp(startTime);



        _getWant(10e8); // 10 wbtc

    }



    function _getWant(uint256 btcAmount) internal {

        _getERC20(wbtc, btcAmount);

        uint256[2] memory liquidity;

        liquidity[1] = IERC20(wbtc).balanceOf(address(this));

        IERC20(wbtc).approve(ren_pool, liquidity[1]);

        ICurveFi_2(ren_pool).add_liquidity(liquidity, 0);

    }



    // **** Tests **** //



    function test_rencrv_v1_withdraw() public {

        _test_withdraw();

    }



    function test_rencrv_v1_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract StrategyCurveSCRVv3_2Test is StrategyCurveFarmTestBase {

    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        want = scrv;



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyCurveSCRVv3_2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        hevm.warp(startTime);



        _getWant(10000000 ether);

    }



    function _getWant(uint256 daiAmount) internal {

        _getERC20(dai, daiAmount);

        uint256[4] memory liquidity;

        liquidity[0] = IERC20(dai).balanceOf(address(this));

        IERC20(dai).approve(susdv2_pool, liquidity[0]);

        ICurveFi_4(susdv2_pool).add_liquidity(liquidity, 0);

    }



    // **** Tests **** //



    function test_scrv_v3_1_withdraw() public {

        _test_withdraw();

    }



    function test_scrv_v3_1_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract StrategyCurveSCRVv4Test is DSTestDefiBase {

    address escrow = 0x5f3b5DfEb7B28CDbD7FAba78963EE202a494e2A2;

    address curveSmartContractChecker = 0xca719728Ef172d0961768581fdF35CB116e0B7a4;



    address governance;

    address strategist;

    address timelock;

    address devfund;

    address treasury;



    PickleJar pickleJar;

    ControllerV4 controller;

    StrategyCurveSCRVv4_1 strategy;

    SCRVVoter scrvVoter;

    CRVLocker crvLocker;



    function setUp() public {

        governance = address(this);

        strategist = address(new User());

        timelock = address(this);

        devfund = address(new User());

        treasury = address(new User());



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        crvLocker = new CRVLocker(governance);



        scrvVoter = new SCRVVoter(governance, address(crvLocker));



        strategy = new StrategyCurveSCRVv4_1(

            address(scrvVoter),

            address(crvLocker),

            governance,

            strategist,

            address(controller),

            timelock

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        scrvVoter.approveStrategy(address(strategy));

        scrvVoter.approveStrategy(governance);

        crvLocker.addVoter(address(scrvVoter));



        hevm.warp(startTime);



        // Approve our strategy on smartContractWhitelist

        // Modify storage value so we are approved by the smart-wallet-white-list

        // storage in solidity - https://ethereum.stackexchange.com/a/41304

        bytes32 key = bytes32(uint256(address(crvLocker)));

        bytes32 pos = bytes32(0); // pos 0 as its the first state variable

        bytes32 loc = keccak256(abi.encodePacked(key, pos));

        hevm.store(curveSmartContractChecker, loc, bytes32(uint256(1)));



        // Make sure our crvLocker is whitelisted

        assertTrue(

            ICurveSmartContractChecker(curveSmartContractChecker).wallets(

                address(crvLocker)

            )

        );

    }



    function _getSCRV(uint256 daiAmount) internal {

        _getERC20(dai, daiAmount);

        uint256[4] memory liquidity;

        liquidity[0] = IERC20(dai).balanceOf(address(this));

        IERC20(dai).approve(susdv2_pool, liquidity[0]);

        ICurveFi_4(susdv2_pool).add_liquidity(liquidity, 0);

    }



    // **** Tests ****



    function test_scrv_v4_1_withdraw() public {

        _getSCRV(10000000 ether); // 1 million DAI

        uint256 _scrv = IERC20(scrv).balanceOf(address(this));

        IERC20(scrv).approve(address(pickleJar), _scrv);

        pickleJar.deposit(_scrv);



        // Deposits to strategy

        pickleJar.earn();



        // Fast forwards

        hevm.warp(block.timestamp + 1 weeks);



        strategy.harvest();



        // Withdraws back to pickleJar

        uint256 _before = IERC20(scrv).balanceOf(address(pickleJar));

        controller.withdrawAll(scrv);

        uint256 _after = IERC20(scrv).balanceOf(address(pickleJar));



        assertTrue(_after > _before);



        _before = IERC20(scrv).balanceOf(address(this));

        pickleJar.withdrawAll();

        _after = IERC20(scrv).balanceOf(address(this));



        assertTrue(_after > _before);



        // Gained some interest

        assertTrue(_after > _scrv);

    }



    function test_scrv_v4_1_get_earn_harvest_rewards() public {

        address dev = controller.devfund();



        // Deposit sCRV, and earn

        _getSCRV(10000000 ether); // 1 million DAI

        uint256 _scrv = IERC20(scrv).balanceOf(address(this));

        IERC20(scrv).approve(address(pickleJar), _scrv);

        pickleJar.deposit(_scrv);

        pickleJar.earn();



        // Fast forward one week

        hevm.warp(block.timestamp + 1 weeks);



        // Call the harvest function

        uint256 _before = pickleJar.balance();

        uint256 _rewardsBefore = IERC20(scrv).balanceOf(treasury);

        User(strategist).execute(address(strategy), 0, "harvest()", "");

        uint256 _after = pickleJar.balance();

        uint256 _rewardsAfter = IERC20(scrv).balanceOf(treasury);



        uint256 earned = _after.sub(_before).mul(1000).div(955);

        uint256 earnedRewards = earned.mul(45).div(1000); // 4.5%

        uint256 actualRewardsEarned = _rewardsAfter.sub(_rewardsBefore);



        // 4.5% performance fee is given

        assertEqApprox(earnedRewards, actualRewardsEarned);



        // Withdraw

        uint256 _devBefore = IERC20(scrv).balanceOf(dev);

        uint256 _stratBal = strategy.balanceOf();

        pickleJar.withdrawAll();

        uint256 _devAfter = IERC20(scrv).balanceOf(dev);



        // 0.175% goes to dev

        uint256 _devFund = _devAfter.sub(_devBefore);

        assertEq(_devFund, _stratBal.mul(175).div(100000));

    }



    function test_scrv_v4_1_lock() public {

        // Deposit sCRV, and earn

        _getSCRV(10000000 ether); // 1 million DAI

        uint256 _scrv = IERC20(scrv).balanceOf(address(this));

        IERC20(scrv).approve(address(pickleJar), _scrv);

        pickleJar.deposit(_scrv);

        pickleJar.earn();



        // Fast forward one week

        hevm.warp(block.timestamp + 1 weeks);



        uint256 _before = IERC20(crv).balanceOf(address(crvLocker));

        // Call the harvest function

        strategy.harvest();

        // Make sure we can open lock

        uint256 _after = IERC20(crv).balanceOf(address(crvLocker));

        assertTrue(_after > _before);



        // Create a lock

        crvLocker.createLock(_after, block.timestamp + 5 weeks);



        // Harvest etc

        hevm.warp(block.timestamp + 1 weeks);

        strategy.harvest();



        // Increase amount

        crvLocker.increaseAmount(IERC20(crv).balanceOf(address(crvLocker)));



        // Increase unlockTime

        crvLocker.increaseUnlockTime(block.timestamp + 5 weeks);



        // Fast forward

        hevm.warp(block.timestamp + 5 weeks + 1 hours);



        // Withdraw

        _before = IERC20(crv).balanceOf(address(crvLocker));

        crvLocker.release();

        _after = IERC20(crv).balanceOf(address(crvLocker));

        assertTrue(_after > _before);

    }

}

contract StrategyUniEthDaiLpV4Test is StrategyUniFarmTestBase {

    function setUp() public {

        want = 0xA478c2975Ab1Ea89e8196811F51A7B7Ade33eB11;

        token1 = dai;



        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyUniEthDaiLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        // Set time

        hevm.warp(startTime);

    }



    // **** Tests ****



    function test_ethdaiv3_1_timelock() public {

        _test_timelock();

    }



    function test_ethdaiv3_1_withdraw_release() public {

        _test_withdraw_release();

    }



    function test_ethdaiv3_1_get_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract StrategyUniEthUsdcLpV4Test is StrategyUniFarmTestBase {

    function setUp() public {

        want = 0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc;

        token1 = usdc;



        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyUniEthUsdcLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        // Set time

        hevm.warp(startTime);

    }



    // **** Tests ****



    function test_ethusdcv3_1_timelock() public {

        _test_timelock();

    }



    function test_ethusdcv3_1_withdraw_release() public {

        _test_withdraw_release();

    }



    function test_ethusdcv3_1_get_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract StrategyUniEthUsdtLpV4Test is StrategyUniFarmTestBase {

    function setUp() public {

        want = 0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852;

        token1 = usdt;



        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyUniEthUsdtLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        // Set time

        hevm.warp(startTime);

    }



    // **** Tests ****



    function test_ethusdtv3_1_timelock() public {

        _test_timelock();

    }



    function test_ethusdtv3_1_withdraw_release() public {

        _test_withdraw_release();

    }



    function test_ethusdtv3_1_get_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract StrategyUniEthWBtcLpV2Test is StrategyUniFarmTestBase {

    function setUp() public {

        want = 0xBb2b8038a1640196FbE3e38816F3e67Cba72D940;

        token1 = wbtc;



        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        strategy = IStrategy(

            address(

                new StrategyUniEthWBtcLpV2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        pickleJar = new PickleJar(

            strategy.want(),

            governance,

            timelock,

            address(controller)

        );



        controller.setJar(strategy.want(), address(pickleJar));

        controller.approveStrategy(strategy.want(), address(strategy));

        controller.setStrategy(strategy.want(), address(strategy));



        // Set time

        hevm.warp(startTime);

    }



    // **** Tests ****



    function test_ethwbtcv1_timelock() public {

        _test_timelock();

    }



    function test_ethwbtcv1_withdraw_release() public {

        _test_withdraw_release();

    }



    function test_ethwbtcv1_get_earn_harvest_rewards() public {

        _test_get_earn_harvest_rewards();

    }

}

contract UniCurveConverterTest is DSTestDefiBase {

    UniCurveConverter uniCurveConverter;



    function setUp() public {

        uniCurveConverter = new UniCurveConverter();

    }



    function _test_uni_curve_converter(address token0, address token1)

        internal

    {

        address lp = univ2Factory.getPair(token0, token1);

        _getUniV2LPToken(lp, 100 ether);



        uint256 _balance = IERC20(lp).balanceOf(address(this));



        IERC20(lp).safeApprove(address(uniCurveConverter), 0);

        IERC20(lp).safeApprove(address(uniCurveConverter), uint256(-1));



        uint256 _before = IERC20(scrv).balanceOf(address(this));

        uniCurveConverter.convert(lp, _balance);

        uint256 _after = IERC20(scrv).balanceOf(address(this));



        // Gets scrv

        assertTrue(_after > _before);

        assertTrue(_after > 0);



        // No token left behind in router

        assertEq(IERC20(token0).balanceOf(address(uniCurveConverter)), 0);

        assertEq(IERC20(token1).balanceOf(address(uniCurveConverter)), 0);

        assertEq(IERC20(weth).balanceOf(address(uniCurveConverter)), 0);



        assertEq(IERC20(dai).balanceOf(address(uniCurveConverter)), 0);

        assertEq(IERC20(usdc).balanceOf(address(uniCurveConverter)), 0);

        assertEq(IERC20(usdt).balanceOf(address(uniCurveConverter)), 0);

        assertEq(IERC20(susd).balanceOf(address(uniCurveConverter)), 0);

    }



    function test_uni_curve_convert_dai_weth() public {

        _test_uni_curve_converter(dai, weth);

    }



    function test_uni_curve_convert_usdt_weth() public {

        _test_uni_curve_converter(usdt, weth);

    }



    function test_uni_curve_convert_wbtc_weth() public {

        _test_uni_curve_converter(wbtc, weth);

    }

}

contract StrategyCurveCurveJarSwapTest is DSTestDefiBase {

    address governance;

    address strategist;

    address devfund;

    address treasury;

    address timelock;



    IStrategy[] curveStrategies;



    PickleJar[] curvePickleJars;



    ControllerV4 controller;



    CurveProxyLogic curveProxyLogic;

    UniswapV2ProxyLogic uniswapV2ProxyLogic;



    address[] curvePools;

    address[] curveLps;



    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        // Curve Strategies

        curveStrategies = new IStrategy[](3);

        curvePickleJars = new PickleJar[](curveStrategies.length);

        curveLps = new address[](curveStrategies.length);

        curvePools = new address[](curveStrategies.length);



        curveLps[0] = three_crv;

        curvePools[0] = three_pool;

        curveStrategies[0] = IStrategy(

            address(

                new StrategyCurve3CRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );

        curveLps[1] = scrv;

        curvePools[1] = susdv2_pool;

        curveStrategies[1] = IStrategy(

            address(

                new StrategyCurveSCRVv3_2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );

        curveLps[2] = ren_crv;

        curvePools[2] = ren_pool;

        curveStrategies[2] = IStrategy(

            address(

                new StrategyCurveRenCRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        // Create PICKLE Jars

        for (uint256 i = 0; i < curvePickleJars.length; i++) {

            curvePickleJars[i] = new PickleJar(

                curveStrategies[i].want(),

                governance,

                timelock,

                address(controller)

            );



            controller.setJar(

                curveStrategies[i].want(),

                address(curvePickleJars[i])

            );

            controller.approveStrategy(

                curveStrategies[i].want(),

                address(curveStrategies[i])

            );

            controller.setStrategy(

                curveStrategies[i].want(),

                address(curveStrategies[i])

            );

        }



        curveProxyLogic = new CurveProxyLogic();

        uniswapV2ProxyLogic = new UniswapV2ProxyLogic();



        controller.approveJarConverter(address(curveProxyLogic));

        controller.approveJarConverter(address(uniswapV2ProxyLogic));



        hevm.warp(startTime);

    }



    function _getCurveLP(address curve, uint256 amount) internal {

        if (curve == ren_pool) {

            _getERC20(wbtc, amount);

            uint256 _wbtc = IERC20(wbtc).balanceOf(address(this));

            IERC20(wbtc).approve(curve, _wbtc);



            uint256[2] memory liquidity;

            liquidity[1] = _wbtc;

            ICurveFi_2(curve).add_liquidity(liquidity, 0);

        } else {

            _getERC20(dai, amount);

            uint256 _dai = IERC20(dai).balanceOf(address(this));

            IERC20(dai).approve(curve, _dai);



            if (curve == three_pool) {

                uint256[3] memory liquidity;

                liquidity[0] = _dai;

                ICurveFi_3(curve).add_liquidity(liquidity, 0);

            } else {

                uint256[4] memory liquidity;

                liquidity[0] = _dai;

                ICurveFi_4(curve).add_liquidity(liquidity, 0);

            }

        }

    }



    // **** Internal functions **** //

    // Theres so many internal functions due to stack blowing up



    // Some post swap checks

    // Checks if there's any leftover funds in the converter contract

    function _post_swap_check(uint256 fromIndex, uint256 toIndex) internal {

        IERC20 token0 = curvePickleJars[fromIndex].token();

        IERC20 token1 = curvePickleJars[toIndex].token();



        uint256 MAX_DUST = 10;



        // No funds left behind

        assertEq(curvePickleJars[fromIndex].balanceOf(address(controller)), 0);

        assertEq(curvePickleJars[toIndex].balanceOf(address(controller)), 0);

        assertTrue(token0.balanceOf(address(controller)) < MAX_DUST);

        assertTrue(token1.balanceOf(address(controller)) < MAX_DUST);



        // Make sure only controller can call 'withdrawForSwap'

        try curveStrategies[fromIndex].withdrawForSwap(0)  {

            revert("!withdraw-for-swap-only-controller");

        } catch {}

    }



    function _test_check_treasury_fee(uint256 _amount, uint256 earned)

        internal

    {

        assertEqApprox(

            _amount.mul(controller.convenienceFee()).div(

                controller.convenienceFeeMax()

            ),

            earned.mul(2)

        );

    }



    function _test_swap_and_check_balances(

        address fromPickleJar,

        address toPickleJar,

        address fromPickleJarUnderlying,

        uint256 fromPickleJarUnderlyingAmount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        uint256 _beforeTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _beforeFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _beforeDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _beforeTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 _ret = controller.swapExactJarForJar(

            fromPickleJar,

            toPickleJar,

            fromPickleJarUnderlyingAmount,

            0, // Min receive amount

            targets,

            data

        );



        uint256 _afterTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _afterFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _afterDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _afterTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 treasuryEarned = _afterTreasury.sub(_beforeTreasury);



        assertEq(treasuryEarned, _afterDev.sub(_beforeDev));

        assertTrue(treasuryEarned > 0);

        _test_check_treasury_fee(fromPickleJarUnderlyingAmount, treasuryEarned);

        assertTrue(_afterFrom < _beforeFrom);

        assertTrue(_afterTo > _beforeTo);

        assertTrue(_afterTo.sub(_beforeTo) > 0);

        assertEq(_afterTo.sub(_beforeTo), _ret);

        assertEq(_afterFrom, 0);

    }



    function _get_uniswap_pl_swap_data(address from, address to)

        internal pure

        returns (bytes memory)

    {

        return

            abi.encodeWithSignature("swapUniswap(address,address)", from, to);

    }



    function _test_curve_curve(

        uint256 fromIndex,

        uint256 toIndex,

        uint256 amount,

        address payable[] memory targets,

        bytes[] memory data

    ) public {

        // Get LP

        _getCurveLP(curvePools[fromIndex], amount);



        // Deposit into pickle jars

        address from = address(curvePickleJars[fromIndex].token());

        uint256 _from = IERC20(from).balanceOf(address(this));

        IERC20(from).approve(address(curvePickleJars[fromIndex]), _from);

        curvePickleJars[fromIndex].deposit(_from);

        curvePickleJars[fromIndex].earn();



        // Approve controller

        uint256 _fromPickleJar = IERC20(address(curvePickleJars[fromIndex]))

            .balanceOf(address(this));

        IERC20(address(curvePickleJars[fromIndex])).approve(

            address(controller),

            _fromPickleJar

        );



        // Swap

        try

            controller.swapExactJarForJar(

                address(curvePickleJars[fromIndex]),

                address(curvePickleJars[toIndex]),

                _fromPickleJar,

                uint256(-1), // Min receive amount

                targets,

                data

            )

         {

            revert("min-receive-amount");

        } catch {}



        _test_swap_and_check_balances(

            address(curvePickleJars[fromIndex]),

            address(curvePickleJars[toIndex]),

            from,

            _fromPickleJar,

            targets,

            data

        );



        _post_swap_check(fromIndex, toIndex);

    }



    // **** Tests ****



    function test_jar_converter_curve_curve_0() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 1;

        uint256 amount = 400e18;



        int128 fromCurveUnderlyingIndex = 0;



        bytes4 toCurveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[4],uint256)"

        );

        uint256 toCurvePoolSize = 4;

        uint256 toCurveUnderlyingIndex = 0;

        address toCurveUnderlying = dai;



        // Remove liquidity

        address fromCurve = curvePools[fromIndex];

        address fromCurveLp = curveLps[fromIndex];



        address payable target0 = payable(address(curveProxyLogic));

        bytes memory data0 = abi.encodeWithSignature(

            "remove_liquidity_one_coin(address,address,int128)",

            fromCurve,

            fromCurveLp,

            fromCurveUnderlyingIndex

        );



        // Add liquidity

        address toCurve = curvePools[toIndex];



        address payable target1 = payable(address(curveProxyLogic));

        bytes memory data1 = abi.encodeWithSignature(

            "add_liquidity(address,bytes4,uint256,uint256,address)",

            toCurve,

            toCurveFunctionSig,

            toCurvePoolSize,

            toCurveUnderlyingIndex,

            toCurveUnderlying

        );



        // Swap

        _test_curve_curve(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(target0, target1),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_curve_1() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 2;

        uint256 amount = 400e18;



        int128 fromCurveUnderlyingIndex = 0;



        bytes4 toCurveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[2],uint256)"

        );

        uint256 toCurvePoolSize = 2;

        uint256 toCurveUnderlyingIndex = 1;

        address toCurveUnderlying = wbtc;



        // Remove liquidity

        address fromCurve = curvePools[fromIndex];

        address fromCurveLp = curveLps[fromIndex];



        bytes memory data0 = abi.encodeWithSignature(

            "remove_liquidity_one_coin(address,address,int128)",

            fromCurve,

            fromCurveLp,

            fromCurveUnderlyingIndex

        );



        // Swap

        bytes memory data1 = _get_uniswap_pl_swap_data(dai, toCurveUnderlying);



        // Add liquidity

        address toCurve = curvePools[toIndex];



        bytes memory data2 = abi.encodeWithSignature(

            "add_liquidity(address,bytes4,uint256,uint256,address)",

            toCurve,

            toCurveFunctionSig,

            toCurvePoolSize,

            toCurveUnderlyingIndex,

            toCurveUnderlying

        );



        _test_curve_curve(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1, data2)

        );

    }



    function test_jar_converter_curve_curve_2() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 0;

        uint256 amount = 400e18;



        int128 fromCurveUnderlyingIndex = 1;



        bytes4 toCurveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );

        uint256 toCurvePoolSize = 3;

        uint256 toCurveUnderlyingIndex = 2;

        address toCurveUnderlying = usdt;



        // Remove liquidity

        address fromCurve = susdv2_deposit; // curvePools[fromIndex];

        address fromCurveLp = curveLps[fromIndex];



        bytes memory data0 = abi.encodeWithSignature(

            "remove_liquidity_one_coin(address,address,int128)",

            fromCurve,

            fromCurveLp,

            fromCurveUnderlyingIndex

        );



        // Swap

        bytes memory data1 = _get_uniswap_pl_swap_data(usdc, usdt);



        // Add liquidity

        address toCurve = curvePools[toIndex];



        bytes memory data2 = abi.encodeWithSignature(

            "add_liquidity(address,bytes4,uint256,uint256,address)",

            toCurve,

            toCurveFunctionSig,

            toCurvePoolSize,

            toCurveUnderlyingIndex,

            toCurveUnderlying

        );



        _test_curve_curve(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1, data2)

        );

    }



    function test_jar_converter_curve_curve_3() public {

        uint256 fromIndex = 2;

        uint256 toIndex = 0;

        uint256 amount = 4e6;



        int128 fromCurveUnderlyingIndex = 1;



        bytes4 toCurveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );

        uint256 toCurvePoolSize = 3;

        uint256 toCurveUnderlyingIndex = 1;

        address toCurveUnderlying = usdc;



        // Remove liquidity

        address fromCurve = curvePools[fromIndex];

        address fromCurveLp = curveLps[fromIndex];



        bytes memory data0 = abi.encodeWithSignature(

            "remove_liquidity_one_coin(address,address,int128)",

            fromCurve,

            fromCurveLp,

            fromCurveUnderlyingIndex

        );



        // Swap

        bytes memory data1 = _get_uniswap_pl_swap_data(wbtc, usdc);



        // Add liquidity

        address toCurve = curvePools[toIndex];



        bytes memory data2 = abi.encodeWithSignature(

            "add_liquidity(address,bytes4,uint256,uint256,address)",

            toCurve,

            toCurveFunctionSig,

            toCurvePoolSize,

            toCurveUnderlyingIndex,

            toCurveUnderlying

        );



        _test_curve_curve(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1, data2)

        );

    }



    function test_jar_converter_curve_curve_4() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 0;

        uint256 amount = 400e18;



        int128 fromCurveUnderlyingIndex = 2;



        bytes4 toCurveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );

        uint256 toCurvePoolSize = 3;

        uint256 toCurveUnderlyingIndex = 1;

        address toCurveUnderlying = usdc;



        // Remove liquidity

        address fromCurve = susdv2_deposit;

        address fromCurveLp = curveLps[fromIndex];



        bytes memory data0 = abi.encodeWithSignature(

            "remove_liquidity_one_coin(address,address,int128)",

            fromCurve,

            fromCurveLp,

            fromCurveUnderlyingIndex

        );



        // Swap

        bytes memory data1 = _get_uniswap_pl_swap_data(usdt, usdc);



        // Add liquidity

        address toCurve = curvePools[toIndex];



        bytes memory data2 = abi.encodeWithSignature(

            "add_liquidity(address,bytes4,uint256,uint256,address)",

            toCurve,

            toCurveFunctionSig,

            toCurvePoolSize,

            toCurveUnderlyingIndex,

            toCurveUnderlying

        );



        _test_curve_curve(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1, data2)

        );

    }

}

contract StrategyCurveUniJarSwapTest is DSTestDefiBase {

    address governance;

    address strategist;

    address devfund;

    address treasury;

    address timelock;



    IStrategy[] curveStrategies;

    IStrategy[] uniStrategies;



    PickleJar[] curvePickleJars;

    PickleJar[] uniPickleJars;



    ControllerV4 controller;



    CurveProxyLogic curveProxyLogic;

    UniswapV2ProxyLogic uniswapV2ProxyLogic;



    address[] curvePools;

    address[] curveLps;



    address[] uniUnderlying;



    // Contract wide variable to avoid stack too deep errors

    uint256 temp;



    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        // Curve Strategies

        curveStrategies = new IStrategy[](3);

        curvePickleJars = new PickleJar[](curveStrategies.length);

        curveLps = new address[](curveStrategies.length);

        curvePools = new address[](curveStrategies.length);



        curveLps[0] = three_crv;

        curvePools[0] = three_pool;

        curveStrategies[0] = IStrategy(

            address(

                new StrategyCurve3CRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        curveLps[1] = scrv;

        curvePools[1] = susdv2_pool;

        curveStrategies[1] = IStrategy(

            address(

                new StrategyCurveSCRVv3_2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        curveLps[2] = ren_crv;

        curvePools[2] = ren_pool;

        curveStrategies[2] = IStrategy(

            address(

                new StrategyCurveRenCRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        // Create PICKLE Jars

        for (uint256 i = 0; i < curvePickleJars.length; i++) {

            curvePickleJars[i] = new PickleJar(

                curveStrategies[i].want(),

                governance,

                timelock,

                address(controller)

            );



            controller.setJar(

                curveStrategies[i].want(),

                address(curvePickleJars[i])

            );

            controller.approveStrategy(

                curveStrategies[i].want(),

                address(curveStrategies[i])

            );

            controller.setStrategy(

                curveStrategies[i].want(),

                address(curveStrategies[i])

            );

        }



        // Uni strategies

        uniStrategies = new IStrategy[](4);

        uniUnderlying = new address[](uniStrategies.length);

        uniPickleJars = new PickleJar[](uniStrategies.length);



        uniUnderlying[0] = dai;

        uniStrategies[0] = IStrategy(

            address(

                new StrategyUniEthDaiLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[1] = usdc;

        uniStrategies[1] = IStrategy(

            address(

                new StrategyUniEthUsdcLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[2] = usdt;

        uniStrategies[2] = IStrategy(

            address(

                new StrategyUniEthUsdtLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[3] = wbtc;

        uniStrategies[3] = IStrategy(

            address(

                new StrategyUniEthWBtcLpV2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        for (uint256 i = 0; i < uniStrategies.length; i++) {

            uniPickleJars[i] = new PickleJar(

                uniStrategies[i].want(),

                governance,

                timelock,

                address(controller)

            );



            controller.setJar(

                uniStrategies[i].want(),

                address(uniPickleJars[i])

            );

            controller.approveStrategy(

                uniStrategies[i].want(),

                address(uniStrategies[i])

            );

            controller.setStrategy(

                uniStrategies[i].want(),

                address(uniStrategies[i])

            );

        }



        curveProxyLogic = new CurveProxyLogic();

        uniswapV2ProxyLogic = new UniswapV2ProxyLogic();



        controller.approveJarConverter(address(curveProxyLogic));

        controller.approveJarConverter(address(uniswapV2ProxyLogic));



        hevm.warp(startTime);

    }



    function _getCurveLP(address curve, uint256 amount) internal {

        if (curve == ren_pool) {

            _getERC20(wbtc, amount);

            uint256 _wbtc = IERC20(wbtc).balanceOf(address(this));

            IERC20(wbtc).approve(curve, _wbtc);



            uint256[2] memory liquidity;

            liquidity[1] = _wbtc;

            ICurveFi_2(curve).add_liquidity(liquidity, 0);

        } else {

            _getERC20(dai, amount);

            uint256 _dai = IERC20(dai).balanceOf(address(this));

            IERC20(dai).approve(curve, _dai);



            if (curve == three_pool) {

                uint256[3] memory liquidity;

                liquidity[0] = _dai;

                ICurveFi_3(curve).add_liquidity(liquidity, 0);

            } else {

                uint256[4] memory liquidity;

                liquidity[0] = _dai;

                ICurveFi_4(curve).add_liquidity(liquidity, 0);

            }

        }

    }



    function _get_primitive_to_lp_data(

        address from,

        address to,

        address dustRecipient

    ) internal pure returns (bytes memory) {

        return

            abi.encodeWithSignature(

                "primitiveToLpTokens(address,address,address)",

                from,

                to,

                dustRecipient

            );

    }



    function _get_curve_remove_liquidity_data(

        address curve,

        address curveLP,

        int128 index

    ) internal pure returns (bytes memory) {

        return

            abi.encodeWithSignature(

                "remove_liquidity_one_coin(address,address,int128)",

                curve,

                curveLP,

                index

            );

    }



    // Some post swap checks

    // Checks if there's any leftover funds in the converter contract

    function _post_swap_check(uint256 fromIndex, uint256 toIndex) internal {

        IERC20 token0 = curvePickleJars[fromIndex].token();

        IUniswapV2Pair token1 = IUniswapV2Pair(

            address(uniPickleJars[toIndex].token())

        );



        uint256 MAX_DUST = 1000;



        // No funds left behind

        assertEq(curvePickleJars[fromIndex].balanceOf(address(controller)), 0);

        assertEq(uniPickleJars[toIndex].balanceOf(address(controller)), 0);

        assertTrue(token0.balanceOf(address(controller)) < MAX_DUST);

        assertTrue(token1.balanceOf(address(controller)) < MAX_DUST);



        // Curve -> UNI LP should be optimal supply

        // Note: We refund the access, which is why its checking this balance

        assertTrue(IERC20(token1.token0()).balanceOf(address(this)) < MAX_DUST);

        assertTrue(IERC20(token1.token1()).balanceOf(address(this)) < MAX_DUST);



        // Make sure only controller can call 'withdrawForSwap'

        try curveStrategies[fromIndex].withdrawForSwap(0)  {

            revert("!withdraw-for-swap-only-controller");

        } catch {}

    }



    function _test_check_treasury_fee(uint256 _amount, uint256 earned)

        internal

    {

        assertEqApprox(

            _amount.mul(controller.convenienceFee()).div(

                controller.convenienceFeeMax()

            ),

            earned.mul(2)

        );

    }



    function _test_swap_and_check_balances(

        address fromPickleJar,

        address toPickleJar,

        address fromPickleJarUnderlying,

        uint256 fromPickleJarUnderlyingAmount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        uint256 _beforeTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _beforeFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _beforeDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _beforeTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 _ret = controller.swapExactJarForJar(

            fromPickleJar,

            toPickleJar,

            fromPickleJarUnderlyingAmount,

            0, // Min receive amount

            targets,

            data

        );



        uint256 _afterTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _afterFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _afterDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _afterTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 treasuryEarned = _afterTreasury.sub(_beforeTreasury);



        assertEq(treasuryEarned, _afterDev.sub(_beforeDev));

        assertTrue(treasuryEarned > 0);

        _test_check_treasury_fee(fromPickleJarUnderlyingAmount, treasuryEarned);

        assertTrue(_afterFrom < _beforeFrom);

        assertTrue(_afterTo > _beforeTo);

        assertTrue(_afterTo.sub(_beforeTo) > 0);

        assertEq(_afterTo.sub(_beforeTo), _ret);

        assertEq(_afterFrom, 0);

    }



    function _test_curve_uni_swap(

        uint256 fromIndex,

        uint256 toIndex,

        uint256 amount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        // Deposit into PickleJars

        address from = address(curvePickleJars[fromIndex].token());



        _getCurveLP(curvePools[fromIndex], amount);



        uint256 _from = IERC20(from).balanceOf(address(this));

        IERC20(from).approve(address(curvePickleJars[fromIndex]), _from);

        curvePickleJars[fromIndex].deposit(_from);

        curvePickleJars[fromIndex].earn();



        // Swap!

        uint256 _fromPickleJar = IERC20(address(curvePickleJars[fromIndex]))

            .balanceOf(address(this));

        IERC20(address(curvePickleJars[fromIndex])).approve(

            address(controller),

            _fromPickleJar

        );



        // Check minimum amount

        try

            controller.swapExactJarForJar(

                address(curvePickleJars[fromIndex]),

                address(uniPickleJars[toIndex]),

                _fromPickleJar,

                uint256(-1), // Min receive amount

                targets,

                data

            )

         {

            revert("min-amount-should-fail");

        } catch {}



        _test_swap_and_check_balances(

            address(curvePickleJars[fromIndex]),

            address(uniPickleJars[toIndex]),

            from,

            _fromPickleJar,

            targets,

            data

        );



        _post_swap_check(fromIndex, toIndex);

    }



    // **** Tests **** //



    function test_jar_converter_curve_uni_0_0() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 0;

        uint256 amount = 400e18;



        address fromUnderlying = dai;

        int128 fromUnderlyingIndex = 0;



        address curvePool = curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_0_1() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 1;

        uint256 amount = 400e18;



        address fromUnderlying = usdc;

        int128 fromUnderlyingIndex = 1;



        address curvePool = curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_0_2() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 2;

        uint256 amount = 400e18;



        address fromUnderlying = usdt;

        int128 fromUnderlyingIndex = 2;



        address curvePool = curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_0_3() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 3;

        uint256 amount = 400e18;



        address fromUnderlying = usdt;

        int128 fromUnderlyingIndex = 2;



        address curvePool = curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_1_0() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 0;

        uint256 amount = 400e18;



        address fromUnderlying = usdt;

        int128 fromUnderlyingIndex = 2;



        address curvePool = susdv2_deposit; // curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_1_1() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 1;

        uint256 amount = 400e18;



        address fromUnderlying = dai;

        int128 fromUnderlyingIndex = 0;



        address curvePool = susdv2_deposit; // curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_1_2() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 2;

        uint256 amount = 400e18;



        address fromUnderlying = dai;

        int128 fromUnderlyingIndex = 0;



        address curvePool = susdv2_deposit; // curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_1_3() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 3;

        uint256 amount = 400e18;



        address fromUnderlying = dai;

        int128 fromUnderlyingIndex = 0;



        address curvePool = susdv2_deposit; // curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_curve_uni_2_3() public {

        uint256 fromIndex = 2;

        uint256 toIndex = 3;

        uint256 amount = 4e6;



        address fromUnderlying = wbtc;

        int128 fromUnderlyingIndex = 1;



        address curvePool = curvePools[fromIndex];

        address toUnderlying = uniUnderlying[toIndex];

        address toWant = univ2Factory.getPair(weth, toUnderlying);



        bytes memory data0 = _get_curve_remove_liquidity_data(

            curvePool,

            curveLps[fromIndex],

            fromUnderlyingIndex

        );



        bytes memory data1 = _get_primitive_to_lp_data(

            fromUnderlying,

            toWant,

            treasury

        );



        _test_curve_uni_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(curveProxyLogic)),

                payable(address(uniswapV2ProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }

}

contract StrategyUniCurveJarSwapTest is DSTestDefiBase {

    address governance;

    address strategist;

    address devfund;

    address treasury;

    address timelock;



    IStrategy[] curveStrategies;

    IStrategy[] uniStrategies;



    PickleJar[] curvePickleJars;

    PickleJar[] uniPickleJars;



    ControllerV4 controller;



    CurveProxyLogic curveProxyLogic;

    UniswapV2ProxyLogic uniswapV2ProxyLogic;



    address[] curvePools;

    address[] curveLps;



    address[] uniUnderlying;



    // Contract wide variable to avoid stack too deep errors

    uint256 temp;



    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        // Curve Strategies

        curveStrategies = new IStrategy[](3);

        curvePickleJars = new PickleJar[](curveStrategies.length);

        curveLps = new address[](curveStrategies.length);

        curvePools = new address[](curveStrategies.length);



        curveLps[0] = three_crv;

        curvePools[0] = three_pool;

        curveStrategies[0] = IStrategy(

            address(

                new StrategyCurve3CRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        curveLps[1] = scrv;

        curvePools[1] = susdv2_pool;

        curveStrategies[1] = IStrategy(

            address(

                new StrategyCurveSCRVv3_2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        curveLps[2] = ren_crv;

        curvePools[2] = ren_pool;

        curveStrategies[2] = IStrategy(

            address(

                new StrategyCurveRenCRVv2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        // Create PICKLE Jars

        for (uint256 i = 0; i < curvePickleJars.length; i++) {

            curvePickleJars[i] = new PickleJar(

                curveStrategies[i].want(),

                governance,

                timelock,

                address(controller)

            );



            controller.setJar(

                curveStrategies[i].want(),

                address(curvePickleJars[i])

            );

            controller.approveStrategy(

                curveStrategies[i].want(),

                address(curveStrategies[i])

            );

            controller.setStrategy(

                curveStrategies[i].want(),

                address(curveStrategies[i])

            );

        }



        // Uni strategies

        uniStrategies = new IStrategy[](4);

        uniUnderlying = new address[](uniStrategies.length);

        uniPickleJars = new PickleJar[](uniStrategies.length);



        uniUnderlying[0] = dai;

        uniStrategies[0] = IStrategy(

            address(

                new StrategyUniEthDaiLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[1] = usdc;

        uniStrategies[1] = IStrategy(

            address(

                new StrategyUniEthUsdcLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[2] = usdt;

        uniStrategies[2] = IStrategy(

            address(

                new StrategyUniEthUsdtLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[3] = wbtc;

        uniStrategies[3] = IStrategy(

            address(

                new StrategyUniEthWBtcLpV2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        for (uint256 i = 0; i < uniStrategies.length; i++) {

            uniPickleJars[i] = new PickleJar(

                uniStrategies[i].want(),

                governance,

                timelock,

                address(controller)

            );



            controller.setJar(

                uniStrategies[i].want(),

                address(uniPickleJars[i])

            );

            controller.approveStrategy(

                uniStrategies[i].want(),

                address(uniStrategies[i])

            );

            controller.setStrategy(

                uniStrategies[i].want(),

                address(uniStrategies[i])

            );

        }



        curveProxyLogic = new CurveProxyLogic();

        uniswapV2ProxyLogic = new UniswapV2ProxyLogic();



        controller.approveJarConverter(address(curveProxyLogic));

        controller.approveJarConverter(address(uniswapV2ProxyLogic));



        hevm.warp(startTime);

    }



    function _getUniLP(

        address lp,

        uint256 ethAmount,

        uint256 otherAmount

    ) internal {

        IUniswapV2Pair fromPair = IUniswapV2Pair(lp);



        address other = fromPair.token0() != weth

            ? fromPair.token0()

            : fromPair.token1();



        _getERC20(other, otherAmount);



        uint256 _other = IERC20(other).balanceOf(address(this));



        IERC20(other).safeApprove(address(univ2), 0);

        IERC20(other).safeApprove(address(univ2), _other);



        univ2.addLiquidityETH{value: ethAmount}(

            other,

            _other,

            0,

            0,

            address(this),

            now + 60

        );

    }



    function _get_uniswap_remove_liquidity_data(address pair)

        internal

        pure

        returns (bytes memory)

    {

        return abi.encodeWithSignature("removeLiquidity(address)", pair);

    }



    function _get_uniswap_lp_tokens_to_primitive(address from, address to)

        internal

        pure

        returns (bytes memory)

    {

        return

            abi.encodeWithSignature(

                "lpTokensToPrimitive(address,address)",

                from,

                to

            );

    }



    function _get_curve_add_liquidity_data(

        address curve,

        bytes4 curveFunctionSig,

        uint256 curvePoolSize,

        uint256 curveUnderlyingIndex,

        address underlying

    ) internal pure returns (bytes memory) {

        return

            abi.encodeWithSignature(

                "add_liquidity(address,bytes4,uint256,uint256,address)",

                curve,

                curveFunctionSig,

                curvePoolSize,

                curveUnderlyingIndex,

                underlying

            );

    }



    // Some post swap checks

    // Checks if there's any leftover funds in the converter contract

    function _post_swap_check(uint256 fromIndex, uint256 toIndex) internal {

        IERC20 token0 = uniPickleJars[fromIndex].token();

        IERC20 token1 = curvePickleJars[toIndex].token();



        // No funds left behind

        assertEq(uniPickleJars[fromIndex].balanceOf(address(controller)), 0);

        assertEq(curvePickleJars[toIndex].balanceOf(address(controller)), 0);

        assertEq(token0.balanceOf(address(controller)), 0);

        assertEq(token1.balanceOf(address(controller)), 0);

        assertEq(IERC20(wbtc).balanceOf(address(controller)), 0);

        // assertEq(IERC20(usdt).balanceOf(address(controller)), 0);

        // assertEq(IERC20(usdc).balanceOf(address(controller)), 0);

        // assertEq(IERC20(susd).balanceOf(address(controller)), 0);

        // assertEq(IERC20(dai).balanceOf(address(controller)), 0);



        // No balance left behind!

        assertEq(token1.balanceOf(address(this)), 0);



        // Make sure only controller can call 'withdrawForSwap'

        try uniStrategies[fromIndex].withdrawForSwap(0)  {

            revert("!withdraw-for-swap-only-controller");

        } catch {}

    }



    function _test_check_treasury_fee(uint256 _amount, uint256 earned)

        internal

    {

        assertEqApprox(

            _amount.mul(controller.convenienceFee()).div(

                controller.convenienceFeeMax()

            ),

            earned.mul(2)

        );

    }



    function _test_swap_and_check_balances(

        address fromPickleJar,

        address toPickleJar,

        address fromPickleJarUnderlying,

        uint256 fromPickleJarUnderlyingAmount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        uint256 _beforeTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _beforeFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _beforeDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _beforeTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 _ret = controller.swapExactJarForJar(

            fromPickleJar,

            toPickleJar,

            fromPickleJarUnderlyingAmount,

            0, // Min receive amount

            targets,

            data

        );



        uint256 _afterTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _afterFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _afterDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _afterTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 treasuryEarned = _afterTreasury.sub(_beforeTreasury);



        assertEq(treasuryEarned, _afterDev.sub(_beforeDev));

        assertTrue(treasuryEarned > 0);

        _test_check_treasury_fee(fromPickleJarUnderlyingAmount, treasuryEarned);

        assertTrue(_afterFrom < _beforeFrom);

        assertTrue(_afterTo > _beforeTo);

        assertTrue(_afterTo.sub(_beforeTo) > 0);

        assertEq(_afterTo.sub(_beforeTo), _ret);

        assertEq(_afterFrom, 0);

    }



    function _test_uni_curve_swap(

        uint256 fromIndex,

        uint256 toIndex,

        uint256 amount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        // Deposit into PickleJars

        address from = address(uniPickleJars[fromIndex].token());



        _getUniLP(from, 1e18, amount);



        uint256 _from = IERC20(from).balanceOf(address(this));

        IERC20(from).approve(address(uniPickleJars[fromIndex]), _from);

        uniPickleJars[fromIndex].deposit(_from);

        uniPickleJars[fromIndex].earn();



        // Swap!

        uint256 _fromPickleJar = IERC20(address(uniPickleJars[fromIndex]))

            .balanceOf(address(this));

        IERC20(address(uniPickleJars[fromIndex])).approve(

            address(controller),

            _fromPickleJar

        );



        // Check minimum amount

        try

            controller.swapExactJarForJar(

                address(uniPickleJars[fromIndex]),

                address(curvePickleJars[toIndex]),

                _fromPickleJar,

                uint256(-1), // Min receive amount

                targets,

                data

            )

         {

            revert("min-amount-should-fail");

        } catch {}



        _test_swap_and_check_balances(

            address(uniPickleJars[fromIndex]),

            address(curvePickleJars[toIndex]),

            from,

            _fromPickleJar,

            targets,

            data

        );



        _post_swap_check(fromIndex, toIndex);

    }



    // **** Tests **** //



    function test_jar_converter_uni_curve_0_0() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 0;

        uint256 amount = 400e18;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 3;

        address curveUnderlying = dai;

        uint256 curveUnderlyingIndex = 0;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_1_0() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 0;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 3;

        address curveUnderlying = dai;

        uint256 curveUnderlyingIndex = 0;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_2_0() public {

        uint256 fromIndex = 2;

        uint256 toIndex = 0;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 3;

        address curveUnderlying = dai;

        uint256 curveUnderlyingIndex = 0;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_3_0() public {

        uint256 fromIndex = 3;

        uint256 toIndex = 0;

        uint256 amount = 4e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 3;

        address curveUnderlying = dai;

        uint256 curveUnderlyingIndex = 0;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[3],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_0_1() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 1;

        uint256 amount = 400e18;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 4;

        address curveUnderlying = usdt;

        uint256 curveUnderlyingIndex = 2;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[4],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_1_1() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 1;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 4;

        address curveUnderlying = usdt;

        uint256 curveUnderlyingIndex = 2;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[4],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_2_1() public {

        uint256 fromIndex = 2;

        uint256 toIndex = 1;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 4;

        address curveUnderlying = usdt;

        uint256 curveUnderlyingIndex = 2;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[4],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_3_1() public {

        uint256 fromIndex = 3;

        uint256 toIndex = 1;

        uint256 amount = 4e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 4;

        address curveUnderlying = usdt;

        uint256 curveUnderlyingIndex = 2;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[4],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_4_1() public {

        uint256 fromIndex = 3;

        uint256 toIndex = 1;

        uint256 amount = 4e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 4;

        address curveUnderlying = usdt;

        uint256 curveUnderlyingIndex = 2;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[4],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_0_2() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 2;

        uint256 amount = 400e18;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 2;

        address curveUnderlying = wbtc;

        uint256 curveUnderlyingIndex = 1;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[2],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_1_2() public {

        uint256 fromIndex = 1;

        uint256 toIndex = 2;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 2;

        address curveUnderlying = wbtc;

        uint256 curveUnderlyingIndex = 1;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[2],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_2_2() public {

        uint256 fromIndex = 2;

        uint256 toIndex = 2;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 2;

        address curveUnderlying = wbtc;

        uint256 curveUnderlyingIndex = 1;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[2],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



    function test_jar_converter_uni_curve_3_2() public {

        uint256 fromIndex = 3;

        uint256 toIndex = 2;

        uint256 amount = 4e6;



        address fromUnderlying = uniUnderlying[fromIndex];



        address curvePool = curvePools[toIndex];

        uint256 curvePoolSize = 2;

        address curveUnderlying = wbtc;

        uint256 curveUnderlyingIndex = 1;

        bytes4 curveFunctionSig = _getFunctionSig(

            "add_liquidity(uint256[2],uint256)"

        );



        bytes memory data0 = _get_uniswap_lp_tokens_to_primitive(

            univ2Factory.getPair(weth, fromUnderlying),

            curveUnderlying

        );



        bytes memory data1 = _get_curve_add_liquidity_data(

            curvePool,

            curveFunctionSig,

            curvePoolSize,

            curveUnderlyingIndex,

            curveUnderlying

        );



        _test_uni_curve_swap(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(

                payable(address(uniswapV2ProxyLogic)),

                payable(address(curveProxyLogic))

            ),

            _getDynamicArray(data0, data1)

        );

    }



}

contract StrategyUniUniJarSwapTest is DSTestDefiBase {

    address governance;

    address strategist;

    address devfund;

    address treasury;

    address timelock;



    IStrategy[] uniStrategies;

    PickleJar[] uniPickleJars;



    ControllerV4 controller;



    CurveProxyLogic curveProxyLogic;

    UniswapV2ProxyLogic uniswapV2ProxyLogic;



    address[] uniUnderlying;



    function setUp() public {

        governance = address(this);

        strategist = address(this);

        devfund = address(new User());

        treasury = address(new User());

        timelock = address(this);



        controller = new ControllerV4(

            governance,

            strategist,

            timelock,

            devfund,

            treasury

        );



        // Uni strategies

        uniStrategies = new IStrategy[](4);

        uniUnderlying = new address[](uniStrategies.length);

        uniPickleJars = new PickleJar[](uniStrategies.length);



        uniUnderlying[0] = dai;

        uniStrategies[0] = IStrategy(

            address(

                new StrategyUniEthDaiLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[1] = usdc;

        uniStrategies[1] = IStrategy(

            address(

                new StrategyUniEthUsdcLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[2] = usdt;

        uniStrategies[2] = IStrategy(

            address(

                new StrategyUniEthUsdtLpV4(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        uniUnderlying[3] = wbtc;

        uniStrategies[3] = IStrategy(

            address(

                new StrategyUniEthWBtcLpV2(

                    governance,

                    strategist,

                    address(controller),

                    timelock

                )

            )

        );



        for (uint256 i = 0; i < uniStrategies.length; i++) {

            uniPickleJars[i] = new PickleJar(

                uniStrategies[i].want(),

                governance,

                timelock,

                address(controller)

            );



            controller.setJar(

                uniStrategies[i].want(),

                address(uniPickleJars[i])

            );

            controller.approveStrategy(

                uniStrategies[i].want(),

                address(uniStrategies[i])

            );

            controller.setStrategy(

                uniStrategies[i].want(),

                address(uniStrategies[i])

            );

        }



        curveProxyLogic = new CurveProxyLogic();

        uniswapV2ProxyLogic = new UniswapV2ProxyLogic();



        controller.approveJarConverter(address(curveProxyLogic));

        controller.approveJarConverter(address(uniswapV2ProxyLogic));



        hevm.warp(startTime);

    }



    function _getUniLP(

        address lp,

        uint256 ethAmount,

        uint256 otherAmount

    ) internal {

        IUniswapV2Pair fromPair = IUniswapV2Pair(lp);



        address other = fromPair.token0() != weth

            ? fromPair.token0()

            : fromPair.token1();



        _getERC20(other, otherAmount);



        uint256 _other = IERC20(other).balanceOf(address(this));



        IERC20(other).safeApprove(address(univ2), 0);

        IERC20(other).safeApprove(address(univ2), _other);



        univ2.addLiquidityETH{value: ethAmount}(

            other,

            _other,

            0,

            0,

            address(this),

            now + 60

        );

    }



    function _get_swap_lp_data(

        address from,

        address to,

        address dustRecipient

    ) internal pure returns (bytes memory) {

        return

            abi.encodeWithSignature(

                "swapUniLPTokens(address,address,address)",

                from,

                to,

                dustRecipient

            );

    }



    function _post_swap_check(uint256 fromIndex, uint256 toIndex) internal {

        IERC20 token0 = uniPickleJars[fromIndex].token();

        IERC20 token1 = uniPickleJars[toIndex].token();



        uint256 MAX_DUST = 10;



        // No funds left behind

        assertEq(uniPickleJars[fromIndex].balanceOf(address(controller)), 0);

        assertEq(uniPickleJars[toIndex].balanceOf(address(controller)), 0);

        assertTrue(token0.balanceOf(address(controller)) < MAX_DUST);

        assertTrue(token1.balanceOf(address(controller)) < MAX_DUST);



        // Make sure only controller can call 'withdrawForSwap'

        try uniStrategies[fromIndex].withdrawForSwap(0)  {

            revert("!withdraw-for-swap-only-controller");

        } catch {}

    }



    function _test_check_treasury_fee(uint256 _amount, uint256 earned)

        internal

    {

        assertEqApprox(

            _amount.mul(controller.convenienceFee()).div(

                controller.convenienceFeeMax()

            ),

            earned.mul(2)

        );

    }



    function _test_swap_and_check_balances(

        address fromPickleJar,

        address toPickleJar,

        address fromPickleJarUnderlying,

        uint256 fromPickleJarUnderlyingAmount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        uint256 _beforeTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _beforeFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _beforeDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _beforeTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 _ret = controller.swapExactJarForJar(

            fromPickleJar,

            toPickleJar,

            fromPickleJarUnderlyingAmount,

            0, // Min receive amount

            targets,

            data

        );



        uint256 _afterTo = IERC20(toPickleJar).balanceOf(address(this));

        uint256 _afterFrom = IERC20(fromPickleJar).balanceOf(address(this));



        uint256 _afterDev = IERC20(fromPickleJarUnderlying).balanceOf(devfund);

        uint256 _afterTreasury = IERC20(fromPickleJarUnderlying).balanceOf(

            treasury

        );



        uint256 treasuryEarned = _afterTreasury.sub(_beforeTreasury);



        assertEq(treasuryEarned, _afterDev.sub(_beforeDev));

        assertTrue(treasuryEarned > 0);

        _test_check_treasury_fee(fromPickleJarUnderlyingAmount, treasuryEarned);

        assertTrue(_afterFrom < _beforeFrom);

        assertTrue(_afterTo > _beforeTo);

        assertTrue(_afterTo.sub(_beforeTo) > 0);

        assertEq(_afterTo.sub(_beforeTo), _ret);

        assertEq(_afterFrom, 0);

    }



    function _test_uni_uni(

        uint256 fromIndex,

        uint256 toIndex,

        uint256 amount,

        address payable[] memory targets,

        bytes[] memory data

    ) internal {

        address from = address(uniPickleJars[fromIndex].token());



        _getUniLP(from, 1e18, amount);



        uint256 _from = IERC20(from).balanceOf(address(this));

        IERC20(from).approve(address(uniPickleJars[fromIndex]), _from);

        uniPickleJars[fromIndex].deposit(_from);

        uniPickleJars[fromIndex].earn();



        // Swap!

        uint256 _fromPickleJar = IERC20(address(uniPickleJars[fromIndex]))

            .balanceOf(address(this));

        IERC20(address(uniPickleJars[fromIndex])).approve(

            address(controller),

            _fromPickleJar

        );



        // Check minimum amount

        try

            controller.swapExactJarForJar(

                address(uniPickleJars[fromIndex]),

                address(uniPickleJars[toIndex]),

                _fromPickleJar,

                uint256(-1), // Min receive amount

                targets,

                data

            )

         {

            revert("min-amount-should-fail");

        } catch {}



        _test_swap_and_check_balances(

            address(uniPickleJars[fromIndex]),

            address(uniPickleJars[toIndex]),

            from,

            _fromPickleJar,

            targets,

            data

        );



        _post_swap_check(fromIndex, toIndex);

    }



    // **** Tests ****



    function test_jar_converter_uni_uni_0() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 1;

        uint256 amount = 400e18;



        address fromUnderlying = uniUnderlying[fromIndex];

        address from = univ2Factory.getPair(weth, fromUnderlying);



        address toUnderlying = uniUnderlying[toIndex];

        address to = univ2Factory.getPair(weth, toUnderlying);



        _test_uni_uni(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(payable(address(uniswapV2ProxyLogic))),

            _getDynamicArray(_get_swap_lp_data(from, to, treasury))

        );

    }



    function test_jar_converter_uni_uni_1() public {

        uint256 fromIndex = 0;

        uint256 toIndex = 2;

        uint256 amount = 400e18;



        address fromUnderlying = uniUnderlying[fromIndex];

        address from = univ2Factory.getPair(weth, fromUnderlying);



        address toUnderlying = uniUnderlying[toIndex];

        address to = univ2Factory.getPair(weth, toUnderlying);



        _test_uni_uni(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(payable(address(uniswapV2ProxyLogic))),

            _getDynamicArray(_get_swap_lp_data(from, to, treasury))

        );

    }



    function test_jar_converter_uni_uni_2() public {

        uint256 fromIndex = 2;

        uint256 toIndex = 3;

        uint256 amount = 400e6;



        address fromUnderlying = uniUnderlying[fromIndex];

        address from = univ2Factory.getPair(weth, fromUnderlying);



        address toUnderlying = uniUnderlying[toIndex];

        address to = univ2Factory.getPair(weth, toUnderlying);



        _test_uni_uni(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(payable(address(uniswapV2ProxyLogic))),

            _getDynamicArray(_get_swap_lp_data(from, to, treasury))

        );

    }



    function test_jar_converter_uni_uni_3() public {

        uint256 fromIndex = 3;

        uint256 toIndex = 2;

        uint256 amount = 4e6;



        address fromUnderlying = uniUnderlying[fromIndex];

        address from = univ2Factory.getPair(weth, fromUnderlying);



        address toUnderlying = uniUnderlying[toIndex];

        address to = univ2Factory.getPair(weth, toUnderlying);



        _test_uni_uni(

            fromIndex,

            toIndex,

            amount,

            _getDynamicArray(payable(address(uniswapV2ProxyLogic))),

            _getDynamicArray(_get_swap_lp_data(from, to, treasury))

        );

    }

}
