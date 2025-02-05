pragma solidity 0.6.11;
pragma experimental ABIEncoderV2;

struct FullAbsoluteTokenAmount {

    AbsoluteTokenAmountMeta base;

    AbsoluteTokenAmountMeta[] underlying;

}

struct AbsoluteTokenAmountMeta {

    AbsoluteTokenAmount absoluteTokenAmount;

    ERC20Metadata erc20metadata;

}

struct ERC20Metadata {

    string name;

    string symbol;

    uint8 decimals;

}

struct AdapterBalance {

    bytes32 protocolAdapterName;

    AbsoluteTokenAmount[] absoluteTokenAmounts;

}

struct AbsoluteTokenAmount {

    address token;

    uint256 amount;

}

struct Component {

    address token;

    uint256 rate;

}

struct TransactionData {

    Action[] actions;

    TokenAmount[] inputs;

    Fee fee;

    AbsoluteTokenAmount[] requiredOutputs;

    uint256 nonce;

}

struct Action {

    bytes32 protocolAdapterName;

    ActionType actionType;

    TokenAmount[] tokenAmounts;

    bytes data;

}

struct TokenAmount {

    address token;

    uint256 amount;

    AmountType amountType;

}

struct Fee {

    uint256 share;

    address beneficiary;

}

enum ActionType { None, Deposit, Withdraw }

enum AmountType { None, Relative, Absolute }

abstract contract ProtocolAdapter {



    /**

     * @dev MUST return amount and type of the given token

     * locked on the protocol by the given account.

     */

    function getBalance(

        address token,

        address account

    )

        public

        view

        virtual

        returns (uint256);

}

contract UniswapV2AssetAdapter is ProtocolAdapter {



    /**

     * @return Amount of Uniswap Pool Tokens held by the given account.

     * @param token Address of the exchange (pair)!

     * @dev Implementation of ProtocolAdapter abstract contract function.

     */

    function getBalance(

        address token,

        address account

    )

        public

        view

        override

        returns (uint256)

    {

        return ERC20(token).balanceOf(account);

    }

}

abstract contract InteractiveAdapter is ProtocolAdapter {



    uint256 internal constant DELIMITER = 1e18;

    address internal constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;



    /**

     * @dev The function must deposit assets to the protocol.

     * @return MUST return assets to be sent back to the `msg.sender`.

     */

    function deposit(

        TokenAmount[] memory tokenAmounts,

        bytes memory data

    )

        public

        payable

        virtual

        returns (address[] memory);



    /**

     * @dev The function must withdraw assets from the protocol.

     * @return MUST return assets to be sent back to the `msg.sender`.

     */

    function withdraw(

        TokenAmount[] memory tokenAmounts,

        bytes memory data

    )

        public

        payable

        virtual

        returns (address[] memory);



    function getAbsoluteAmountDeposit(

        TokenAmount memory tokenAmount

    )

        internal

        view

        virtual

        returns (uint256)

    {

        address token = tokenAmount.token;

        uint256 amount = tokenAmount.amount;

        AmountType amountType = tokenAmount.amountType;



        require(

            amountType == AmountType.Relative || amountType == AmountType.Absolute,

            "IA: bad amount type"

        );

        if (amountType == AmountType.Relative) {

            require(amount <= DELIMITER, "IA: bad amount");



            uint256 balance;

            if (token == ETH) {

                balance = address(this).balance;

            } else {

                balance = ERC20(token).balanceOf(address(this));

            }



            if (amount == DELIMITER) {

                return balance;

            } else {

                return mul(balance, amount) / DELIMITER;

            }

        } else {

            return amount;

        }

    }



    function getAbsoluteAmountWithdraw(

        TokenAmount memory tokenAmount

    )

        internal

        view

        virtual

        returns (uint256)

    {

        address token = tokenAmount.token;

        uint256 amount = tokenAmount.amount;

        AmountType amountType = tokenAmount.amountType;



        require(

            amountType == AmountType.Relative || amountType == AmountType.Absolute,

            "IA: bad amount type"

        );

        if (amountType == AmountType.Relative) {

            require(amount <= DELIMITER, "IA: bad amount");



            uint256 balance = getBalance(token, address(this));

            if (amount == DELIMITER) {

                return balance;

            } else {

                return mul(balance, amount) / DELIMITER;

            }

        } else {

            return amount;

        }

    }



    function mul(

        uint256 a,

        uint256 b

    )

        internal

        pure

        returns (uint256)

    {

        if (a == 0) {

            return 0;

        }



        uint256 c = a * b;

        require(c / a == b, "IA: mul overflow");



        return c;

    }

}

interface UniswapV2Pair {

    function mint(address) external returns (uint256);

    function burn(address) external returns (uint256, uint256);

    function getReserves() external view returns (uint112, uint112);

    function token0() external view returns (address);

    function token1() external view returns (address);

}

contract UniswapV2AssetInteractiveAdapter is InteractiveAdapter, UniswapV2AssetAdapter {

    using SafeERC20 for ERC20;



    address internal constant WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;



    /**

     * @notice Deposits tokens to the Uniswap pool (pair).

     * @param tokenAmounts Array with one element - TokenAmount struct with

     * underlying tokens addresses, underlying tokens amounts to be deposited, and amount types.

     * @param data ABI-encoded additional parameters:

     *     - pairAddress - pair address.

     * @return tokensToBeWithdrawn Array with one element - UNI-token (pair) address.

     * @dev Implementation of InteractiveAdapter function.

     */

    function deposit(

        TokenAmount[] memory tokenAmounts,

        bytes memory data

    )

        public

        payable

        override

        returns (address[] memory tokensToBeWithdrawn)

    {

        require(tokenAmounts.length == 2, "ULIA: should be 2 tokenAmounts");



        address pairAddress = abi.decode(data, (address));

        tokensToBeWithdrawn = new address[](1);

        tokensToBeWithdrawn[0] = pairAddress;



        uint256 amount0 = getAbsoluteAmountDeposit(tokenAmounts[0]);

        uint256 amount1 = getAbsoluteAmountDeposit(tokenAmounts[1]);



        uint256 reserve0;

        uint256 reserve1;

        if (tokenAmounts[0].token == UniswapV2Pair(pairAddress).token0()) {

            (reserve0, reserve1) = UniswapV2Pair(pairAddress).getReserves();

        } else {

            (reserve1, reserve0) = UniswapV2Pair(pairAddress).getReserves();

        }



        uint256 amount1Optimal = amount0 * reserve1 / reserve0;

        if (amount1Optimal < amount1) {

            amount1 = amount1Optimal;

        } else if (amount1Optimal > amount1) {

            amount0 = amount1 * reserve0 / reserve1;

        }



        ERC20(tokenAmounts[0].token).safeTransfer(pairAddress, amount0, "ULIA[1]");

        ERC20(tokenAmounts[1].token).safeTransfer(pairAddress, amount1, "ULIA[2]");



        try UniswapV2Pair(pairAddress).mint(

            address(this)

        ) returns (uint256) { // solhint-disable-line no-empty-blocks

        } catch Error(string memory reason) {

            revert(reason);

        } catch {

            revert("ULIA: deposit fail");

        }

    }



    /**

     * @notice Withdraws tokens from the Uniswap pool.

     * @param tokenAmounts Array with one element - TokenAmount struct with

     * UNI token address, UNI token amount to be redeemed, and amount type.

     * @return tokensToBeWithdrawn Array with two elements - underlying tokens.

     * @dev Implementation of InteractiveAdapter function.

     */

    function withdraw(

        TokenAmount[] memory tokenAmounts,

        bytes memory

    )

        public

        payable

        override

        returns (address[] memory tokensToBeWithdrawn)

    {

        require(tokenAmounts.length == 1, "ULIA: should be 1 tokenAmount");



        address token = tokenAmounts[0].token;

        uint256 amount = getAbsoluteAmountWithdraw(tokenAmounts[0]);



        tokensToBeWithdrawn = new address[](2);

        tokensToBeWithdrawn[0] = UniswapV2Pair(token).token0();

        tokensToBeWithdrawn[1] = UniswapV2Pair(token).token1();



        ERC20(token).safeTransfer(token, amount, "ULIA[3]");



        try UniswapV2Pair(token).burn(

            address(this)

        ) returns (uint256, uint256) { // solhint-disable-line no-empty-blocks

        } catch Error(string memory reason) {

            revert(reason);

        } catch {

            revert("ULIA: withdraw fail");

        }

    }

}

interface ERC20 {

    function approve(address, uint256) external returns (bool);

    function transfer(address, uint256) external returns (bool);

    function transferFrom(address, address, uint256) external returns (bool);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    function totalSupply() external view returns (uint256);

    function balanceOf(address) external view returns (uint256);

    function allowance(address, address) external view returns (uint256);

}

library SafeERC20 {



    function safeTransfer(

        ERC20 token,

        address to,

        uint256 value,

        string memory location

    )

        internal

    {

        callOptionalReturn(

            token,

            abi.encodeWithSelector(

                token.transfer.selector,

                to,

                value

            ),

            "transfer",

            location

        );

    }



    function safeTransferFrom(

        ERC20 token,

        address from,

        address to,

        uint256 value,

        string memory location

    )

        internal

    {

        callOptionalReturn(

            token,

            abi.encodeWithSelector(

                token.transferFrom.selector,

                from,

                to,

                value

            ),

            "transferFrom",

            location

        );

    }



    function safeApprove(

        ERC20 token,

        address spender,

        uint256 value,

        string memory location

    )

        internal

    {

        require(

            (value == 0) || (token.allowance(address(this), spender) == 0),

            "SafeERC20: bad approve call"

        );

        callOptionalReturn(

            token,

            abi.encodeWithSelector(

                token.approve.selector,

                spender,

                value

            ),

            "approve",

            location

        );

    }



    /**

     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract),

     * relaxing the requirement on the return value: the return value is optional

     * (but if data is returned, it must not be false).

     * @param token The token targeted by the call.

     * @param data The call data (encoded using abi.encode or one of its variants).

     * @param location Location of the call (for debug).

     */

    function callOptionalReturn(

        ERC20 token,

        bytes memory data,

        string memory functionName,

        string memory location

    )

        private

    {

        // We need to perform a low level call here, to bypass Solidity's return data size checking

        // mechanism, since we're implementing it ourselves.



        // We implement two-steps call as callee is a contract is a responsibility of a caller.

        //  1. The call itself is made, and success asserted

        //  2. The return value is decoded, which in turn checks the size of the returned data.



        // solhint-disable-next-line avoid-low-level-calls

        (bool success, bytes memory returndata) = address(token).call(data);

        require(

            success,

            string(

                abi.encodePacked(

                    "SafeERC20: ",

                    functionName,

                    " failed in ",

                    location

                )

            )

        );



        if (returndata.length > 0) { // Return data is optional

            require(

                abi.decode(returndata, (bool)),

                string(

                    abi.encodePacked(

                        "SafeERC20: ",

                        functionName,

                        " returned false in ",

                        location

                    )

                )

            );

        }

    }

}
