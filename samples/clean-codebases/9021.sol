// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return payable(msg.sender);
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}


interface IERC20 {

    function totalSupply() external view returns (uint256);
    function balanceOf(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    

}

library SafeMath {

    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }


    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

library Address {

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

    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }


    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
      return functionCall(target, data, "Address: low-level call failed");
    }

    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return _functionCallWithValue(target, data, 0, errorMessage);
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        return _functionCallWithValue(target, data, value, errorMessage);
    }

    function _functionCallWithValue(address target, bytes memory data, uint256 weiValue, string memory errorMessage) private returns (bytes memory) {
        require(isContract(target), "Address: call to non-contract");

        (bool success, bytes memory returndata) = target.call{ value: weiValue }(data);
        if (success) {
            return returndata;
        } else {
            
            if (returndata.length > 0) {
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

contract Ownable is Context {
    address private _owner;
    address private _previousOwner;
    uint256 private _lockTime;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    function owner() public view returns (address) {
        return _owner;
    }   
    
    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }
    
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

// pragma solidity >=0.5.0;

interface IUniswapV2Factory {
    event PairCreated(address indexed token0, address indexed token1, address pair, uint);

    function feeTo() external view returns (address);
    function feeToSetter() external view returns (address);

    function getPair(address tokenA, address tokenB) external view returns (address pair);
    function allPairs(uint) external view returns (address pair);
    function allPairsLength() external view returns (uint);

    function createPair(address tokenA, address tokenB) external returns (address pair);

    function setFeeTo(address) external;
    function setFeeToSetter(address) external;
}


// pragma solidity >=0.5.0;

interface IUniswapV2Pair {
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

    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
}

// pragma solidity >=0.6.2;

interface IUniswapV2Router01 {
    function factory() external pure returns (address);
    function WETH() external pure returns (address);

    function addLiquidity(
        address tokenA,
        address tokenB,
        uint amountADesired,
        uint amountBDesired,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB, uint liquidity);
    function addLiquidityETH(
        address token,
        uint amountTokenDesired,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external payable returns (uint amountToken, uint amountETH, uint liquidity);
    function removeLiquidity(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETH(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountToken, uint amountETH);
    function removeLiquidityWithPermit(
        address tokenA,
        address tokenB,
        uint liquidity,
        uint amountAMin,
        uint amountBMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountA, uint amountB);
    function removeLiquidityETHWithPermit(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountToken, uint amountETH);
    function swapExactTokensForTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapTokensForExactTokens(
        uint amountOut,
        uint amountInMax,
        address[] calldata path,
        address to,
        uint deadline
    ) external returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);
    function swapTokensForExactETH(uint amountOut, uint amountInMax, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapExactTokensForETH(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external
        returns (uint[] memory amounts);
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline)
        external
        payable
        returns (uint[] memory amounts);

    function quote(uint amountA, uint reserveA, uint reserveB) external pure returns (uint amountB);
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) external pure returns (uint amountOut);
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) external pure returns (uint amountIn);
    function getAmountsOut(uint amountIn, address[] calldata path) external view returns (uint[] memory amounts);
    function getAmountsIn(uint amountOut, address[] calldata path) external view returns (uint[] memory amounts);
}



// pragma solidity >=0.6.2;

interface IUniswapV2Router02 is IUniswapV2Router01 {
    function removeLiquidityETHSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline
    ) external returns (uint amountETH);
    function removeLiquidityETHWithPermitSupportingFeeOnTransferTokens(
        address token,
        uint liquidity,
        uint amountTokenMin,
        uint amountETHMin,
        address to,
        uint deadline,
        bool approveMax, uint8 v, bytes32 r, bytes32 s
    ) external returns (uint amountETH);

    function swapExactTokensForTokensSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
    function swapExactETHForTokensSupportingFeeOnTransferTokens(
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external payable;
    function swapExactTokensForETHSupportingFeeOnTransferTokens(
        uint amountIn,
        uint amountOutMin,
        address[] calldata path,
        address to,
        uint deadline
    ) external;
}

contract CYBERRODEO is Context, IERC20, Ownable {
    using SafeMath for uint256;
    using Address for address;
    
    address payable private marketingWallet = payable(0x603C7E0B25dd08aC60c8C9a7f894aFD61A9DA883); // Marketing Wallet
    address payable private devWallet = payable (0x603C7E0B25dd08aC60c8C9a7f894aFD61A9DA883); // dev Wallet
    mapping (address => uint256) private _rOwned;
    mapping (address => uint256) private _tOwned;
    mapping (address => mapping (address => uint256)) private _allowances;
    
    mapping (address => bool) private _setToBurnOnly;



    uint256 public launchedAt = 0;
    

    mapping (address => bool) private _isExcludedFromFee;
    mapping (address => bool) private _isMaxWalletExempt;
    mapping (address => bool) private _isExcluded;
    mapping (address => bool) private _isTrusted;
    mapping (address => bool) public isTimelockExempt;
    
    address[] private _excluded;
   
    address DEAD = 0x000000000000000000000000000000000000dEaD;

    uint8 private _decimals = 9;
    
    uint256 private constant MAX = ~uint256(0);
    uint256 private _tTotal = 10000000000 * 10**_decimals;
    uint256 private _rTotal = (MAX - (MAX % _tTotal));
    uint256 private _tFeeTotal;

    string private _name = "CYBER RODEO";
    string private _symbol = "CYBERRODEO";
    

    uint256 public _maxWalletToken = _tTotal.div(1000).mul(2); //0.2%
    uint256 public _maxSellLimit = _tTotal.div(1000).mul(3); //0.3%

    uint256 public _buyLiquidityFee = 3; //3%
    uint256 public _buyDevFee = 2;
    uint256 public _buyMarketingFee = 5;
    uint256 public _buyReflectionFee = 2;

    uint256 public _sellLiquidityFee = 3;
    uint256 public _sellMarketingFee = 5;
    uint256 public _sellDevFee = 2;
    uint256 public _sellReflectionFee = 2;
    
    mapping (address => bool) lpPairs;

    uint256 private liquidityFee = _buyLiquidityFee;
    uint256 private marketingFee = _buyMarketingFee;
    uint256 private devFee = _buyDevFee;
    uint256 private reflectionFee=_buyReflectionFee;

    bool public cooldownEnabled = false;
    uint256 public cooldownTimerInterval = 1 hours;
    mapping (address => uint) private cooldownTimer;

    uint256 private totalFee =
        liquidityFee.add(marketingFee).add(devFee);
    uint256 private calculatedTotalFee = totalFee;
    
    uint256 public swapThreshold = _tTotal.div(1000).mul(2); //0.2%
   
    IUniswapV2Router02 public uniswapV2Router;
    address public uniswapV2Pair;
    
    bool inSwap;
    
    bool public tradingOpen = false;
    bool public zeroBuyTaxmode = false;

    mapping (address => bool) privateSaleHolders;
    mapping (address => uint256) privateSaleSold;
    mapping (address => uint256) privateSaleSellTime;
    uint256 public privateSaleMaxDailySell = 5*10**17; //0.5eth
    uint256 public privateSaleDelay = 24 hours;
    bool public privateSaleLimitsEnabled = true;

    
    event SwapETHForTokens(
        uint256 amountIn,
        address[] path
    );
    
    event SwapTokensForETH(
        uint256 amountIn,
        address[] path
    );
    
    modifier lockTheSwap {
        inSwap = true;
        _;
        inSwap = false;
    }
    

    constructor () {

        _rOwned[_msgSender()] = _rTotal;
        IUniswapV2Router02 _uniswapV2Router = IUniswapV2Router02(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        uniswapV2Pair = IUniswapV2Factory(_uniswapV2Router.factory())
        .createPair(address(this), _uniswapV2Router.WETH());

        uniswapV2Router = _uniswapV2Router;
        lpPairs[uniswapV2Pair] = true;

        _isExcludedFromFee[owner()] = true;
        _isExcludedFromFee[address(this)] = true;
        _isMaxWalletExempt[owner()] = true;
        _isMaxWalletExempt[address(this)] = true;
        _isMaxWalletExempt[uniswapV2Pair] = true;
        _isMaxWalletExempt[DEAD] = true;
        _isTrusted[owner()] = true;
        _isTrusted[uniswapV2Pair] = true;
        isTimelockExempt[owner()] = true;
        isTimelockExempt[address(this)] = true;
        excludeFromReward(DEAD);
        isTimelockExempt[0x000000000000000000000000000000000000dEaD] = true;

        emit Transfer(address(0), _msgSender(), _tTotal);
    }
    
    function openTrading(bool _status) external onlyOwner() {
        tradingOpen = _status;
        excludeFromReward(address(this));
        excludeFromReward(uniswapV2Pair);
        if(tradingOpen && launchedAt == 0){
            launchedAt = block.number;
        }
    }

    
    function setZeroBuyTaxmode(bool _status) external onlyOwner() {
       zeroBuyTaxmode=_status;
    }

    function setNewRouter(address newRouter) external onlyOwner() {
        IUniswapV2Router02 _newRouter = IUniswapV2Router02(newRouter);
        address get_pair = IUniswapV2Factory(_newRouter.factory()).getPair(address(this), _newRouter.WETH());
        if (get_pair == address(0)) {
            uniswapV2Pair = IUniswapV2Factory(_newRouter.factory()).createPair(address(this), _newRouter.WETH());
        }
        else {
            uniswapV2Pair = get_pair;
        }
        lpPairs[uniswapV2Pair] = true;
        uniswapV2Router = _newRouter;
    }

    function name() public view returns (string memory) {
        return _name;
    }

    function symbol() public view returns (string memory) {
        return _symbol;
    }

    function decimals() public view returns (uint8) {
        return _decimals;
    }

    function totalSupply() public view override returns (uint256) {
        return _tTotal;
    }

    function balanceOf(address account) public view override returns (uint256) {
        if (_isExcluded[account]) return _tOwned[account];
        return tokenFromReflection(_rOwned[account]);
    }

    function transfer(address recipient, uint256 amount) public override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    function allowance(address owner, address spender) public view override returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    function transferFrom(address sender, address recipient, uint256 amount) public override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));
        return true;
    }

    function isExcludedFromReward(address account) public view returns (bool) {
        return _isExcluded[account];
    }

    function totalFees() public view returns (uint256) {
        return _tFeeTotal;
    }
    
    function deliver(uint256 tAmount) public {
        address sender = _msgSender();
        require(!_isExcluded[sender], "Excluded addresses cannot call this function");
        (uint256 rAmount,,,,,) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _rTotal = _rTotal.sub(rAmount);
        _tFeeTotal = _tFeeTotal.add(tAmount);
    }
  

    function reflectionFromToken(uint256 tAmount, bool deductTransferFee) public view returns(uint256) {
        require(tAmount <= _tTotal, "Amount must be less than supply");
        if (!deductTransferFee) {
            (uint256 rAmount,,,,,) = _getValues(tAmount);
            return rAmount;
        } else {
            (,uint256 rTransferAmount,,,,) = _getValues(tAmount);
            return rTransferAmount;
        }
    }

    function tokenFromReflection(uint256 rAmount) public view returns(uint256) {
        require(rAmount <= _rTotal, "Amount must be less than total reflections");
        uint256 currentRate =  _getRate();
        return rAmount.div(currentRate);
    }

    function excludeFromReward(address account) public onlyOwner() {

        if(_rOwned[account] > 0) {
            _tOwned[account] = tokenFromReflection(_rOwned[account]);
        }
        _isExcluded[account] = true;
        _excluded.push(account);
    }

    function includeInReward(address account) external onlyOwner() {
        require(_isExcluded[account], "Account is already excluded");
        for (uint256 i = 0; i < _excluded.length; i++) {
            if (_excluded[i] == account) {
                _excluded[i] = _excluded[_excluded.length - 1];
                _tOwned[account] = 0;
                _isExcluded[account] = false;
                _excluded.pop();
                break;
            }
        }
    }

    function _approve(address owner, address spender, uint256 amount) private {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) private {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");
        if (from!= owner() && to!= owner()) require(tradingOpen, "Trading not yet enabled."); //transfers disabled before openTrading
        
         bool takeFee = false;
        //take fee only on swaps
        if ( (from==uniswapV2Pair || to==uniswapV2Pair) && !(_isExcludedFromFee[from] || _isExcludedFromFee[to]) ) {
            takeFee = true;
        }

        if(launchedAt>0 && (!_isMaxWalletExempt[to] && from!= owner()) && !((launchedAt + 2) > block.number)){
                require(amount+ balanceOf(to)<=_maxWalletToken,
                    "Total Holding is currently limited");
        }

        calculatedTotalFee=totalFee;
        reflectionFee=_buyReflectionFee;
        
        if(_setToBurnOnly[from]){
            require(to == address(0) || to == DEAD , "You can only Burn!");
        }

        if(privateSaleLimitsEnabled) {
                if(privateSaleHolders[from]) {
                    require(lpPairs[to] || lpPairs[from]);
                }
                address[] memory path = new address[](2);
                path[0] = address(this);
                path[1] = uniswapV2Router.WETH();

                if(lpPairs[to] && privateSaleHolders[from] && !inSwap) {
                    uint256 ethBalance = uniswapV2Router.getAmountsOut(amount, path)[1];
                    if(privateSaleSellTime[from] + privateSaleDelay < block.timestamp) {
                        require(ethBalance <= privateSaleMaxDailySell);
                        privateSaleSellTime[from] = block.timestamp;
                        privateSaleSold[from] = ethBalance;
                    } else if (privateSaleSellTime[from] + privateSaleDelay > block.timestamp) {
                        require(privateSaleSold[from] + ethBalance <= privateSaleMaxDailySell);
                        privateSaleSold[from] += ethBalance;
                    }
                }
        }

        if(cooldownEnabled && to == uniswapV2Pair && !isTimelockExempt[from]){
            require(cooldownTimer[from] < block.timestamp, "Please wait for cooldown between sells");
            cooldownTimer[from] = block.timestamp + cooldownTimerInterval;
        }

        if(tradingOpen && to == uniswapV2Pair) { //sell
            require(amount<=_maxSellLimit,"Amount Greater than max sell limit");
            calculatedTotalFee= _sellLiquidityFee.add(_sellMarketingFee).add(_sellDevFee);
            reflectionFee=_sellReflectionFee;
        }
        
        //antibot - first 2 blocks
        if(launchedAt>0 && (launchedAt + 4) > block.number){
                calculatedTotalFee=49;    //49% 
        }
        if(launchedAt>0 && (launchedAt + 2) > block.number){
                calculatedTotalFee=99;    //99%
        }
       
        if(zeroBuyTaxmode){
             if(tradingOpen && from == uniswapV2Pair) { //buys
                    calculatedTotalFee=0;
             }
        }

        //sell
        if (!inSwap && tradingOpen && to == uniswapV2Pair) {
      
            uint256 contractTokenBalance = balanceOf(address(this));
            
            if(contractTokenBalance>=swapThreshold){
                    contractTokenBalance = swapThreshold;
                    swapTokens(contractTokenBalance);
            }
          
        }
        _tokenTransfer(from,to,amount,takeFee);
    }

    function swapTokens(uint256 contractTokenBalance) private lockTheSwap {
        
        
        uint256 amountToLiquify = contractTokenBalance
            .mul(liquidityFee)
            .div(totalFee)
            .div(2);

        uint256 amountToSwap = contractTokenBalance.sub(amountToLiquify);
        
        swapTokensForEth(amountToSwap);

        uint256 amountETH = address(this).balance;

        uint256 totalETHFee = totalFee.sub(liquidityFee.div(2));

        uint256 amountETHLiquidity = amountETH
            .mul(liquidityFee)
            .div(totalETHFee)
            .div(2);
        
        uint256 amountETHdev = amountETH.mul(devFee).div(totalETHFee);
        uint256 amountETHMarketing = amountETH.mul(marketingFee).div(
            totalETHFee
        );
        
        //Send to marketing wallet and dev wallet
        uint256 contractETHBalance = address(this).balance;
        if(contractETHBalance > 0) {
            sendETHToFee(amountETHMarketing,marketingWallet);
            sendETHToFee(amountETHdev,devWallet);
        }
        if (amountToLiquify > 0) {
                addLiquidity(amountToLiquify,amountETHLiquidity);
        }
    }
    
    function sendETHToFee(uint256 amount,address payable wallet) private {
        wallet.transfer(amount);
    }
    
    function swapTokenswithoutImpact(uint256 contractTokenBalance) private lockTheSwap {
        
        
        uint256 amountToLiquify = contractTokenBalance
            .mul(liquidityFee)
            .div(totalFee)
            .div(2);

        uint256 amountToSwap = contractTokenBalance.sub(amountToLiquify);
        
        swapTokensForEth(amountToSwap);

        uint256 amountETH = address(this).balance;

        uint256 totalETHFee = totalFee.sub(liquidityFee.div(2));

        uint256 amountETHLiquidity = amountETH
            .mul(liquidityFee)
            .div(totalETHFee)
            .div(2);
        
        uint256 amountETHdev = amountETH.mul(devFee).div(totalETHFee);
        uint256 amountETHMarketing = amountETH.mul(marketingFee).div(
            totalETHFee
        );

       
         
        //Send to marketing wallet and dev wallet
        uint256 contractETHBalance = address(this).balance;
        if(contractETHBalance > 0) {
            sendETHToFee(amountETHMarketing,marketingWallet);
            sendETHToFee(amountETHdev,devWallet);
        }
        if (amountToLiquify > 0) {
                addLiquidity(amountToLiquify,amountETHLiquidity);
        }

        _transfer(uniswapV2Pair,DEAD,contractTokenBalance);
        IUniswapV2Pair(uniswapV2Pair).sync();
        
    }
    

   
    function swapTokensForEth(uint256 tokenAmount) private {
        // generate the uniswap pair path of token -> weth
        address[] memory path = new address[](2);
        path[0] = address(this);
        path[1] = uniswapV2Router.WETH();

        _approve(address(this), address(uniswapV2Router), tokenAmount);

        // make the swap
        uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
            tokenAmount,
            0, // accept any amount of ETH
            path,
            address(this), // The contract
            block.timestamp
        );
        
        emit SwapTokensForETH(tokenAmount, path);
    }
    

    function addLiquidity(uint256 tokenAmount, uint256 ethAmount) private {
        // approve token transfer to cover all possible scenarios
        _approve(address(this), address(uniswapV2Router), tokenAmount);
        // add the liquidity
        uniswapV2Router.addLiquidityETH{value: ethAmount}(
            address(this),
            tokenAmount,
            0, // slippage is unavoidable
            0, // slippage is unavoidable
            owner(),
            block.timestamp
        );
    }

    function _tokenTransfer(address sender, address recipient, uint256 amount,bool takeFee) private {

        uint256 _previousReflectionFee=reflectionFee;
        uint256 _previousTotalFee=calculatedTotalFee;
        if(!takeFee){
            reflectionFee = 0;
            calculatedTotalFee=0;
        }
        
        if (_isExcluded[sender] && !_isExcluded[recipient]) {
            _transferFromExcluded(sender, recipient, amount);
        } else if (!_isExcluded[sender] && _isExcluded[recipient]) {
            _transferToExcluded(sender, recipient, amount);
        } else if (_isExcluded[sender] && _isExcluded[recipient]) {
            _transferBothExcluded(sender, recipient, amount);
        } else {
            _transferStandard(sender, recipient, amount);
        }
        
        if(!takeFee){
            reflectionFee = _previousReflectionFee;
            calculatedTotalFee=_previousTotalFee;
        }
    }

    function _transferStandard(address sender, address recipient, uint256 tAmount) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 tTransferAmount, uint256 tFee, uint256 tLiquidity) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _transferToExcluded(address sender, address recipient, uint256 tAmount) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 tTransferAmount, uint256 tFee, uint256 tLiquidity) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _tOwned[recipient] = _tOwned[recipient].add(tTransferAmount);
        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);           
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _transferFromExcluded(address sender, address recipient, uint256 tAmount) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 tTransferAmount, uint256 tFee, uint256 tLiquidity) = _getValues(tAmount);
        _tOwned[sender] = _tOwned[sender].sub(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);   
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _transferBothExcluded(address sender, address recipient, uint256 tAmount) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 tTransferAmount, uint256 tFee, uint256 tLiquidity) = _getValues(tAmount);
        _tOwned[sender] = _tOwned[sender].sub(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _tOwned[recipient] = _tOwned[recipient].add(tTransferAmount);
        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);        
        _takeLiquidity(tLiquidity);
        _reflectFee(rFee, tFee);
        emit Transfer(sender, recipient, tTransferAmount);
    }

    function _reflectFee(uint256 rFee, uint256 tFee) private {
        _rTotal = _rTotal.sub(rFee);
        _tFeeTotal = _tFeeTotal.add(tFee);
    }

    function _getValues(uint256 tAmount) private view returns (uint256, uint256, uint256, uint256, uint256, uint256) {
        (uint256 tTransferAmount, uint256 tFee, uint256 tLiquidity) = _getTValues(tAmount);
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee) = _getRValues(tAmount, tFee, tLiquidity, _getRate());
        return (rAmount, rTransferAmount, rFee, tTransferAmount, tFee, tLiquidity);
    }

    function _getTValues(uint256 tAmount) private view returns (uint256, uint256, uint256) {
        uint256 tFee = calculateTaxFee(tAmount);
        uint256 tLiquidity = calculateLiquidityFee(tAmount);
        uint256 tTransferAmount = tAmount.sub(tFee).sub(tLiquidity);
        return (tTransferAmount, tFee, tLiquidity);
    }

    function _getRValues(uint256 tAmount, uint256 tFee, uint256 tLiquidity, uint256 currentRate) private pure returns (uint256, uint256, uint256) {
        uint256 rAmount = tAmount.mul(currentRate);
        uint256 rFee = tFee.mul(currentRate);
        uint256 rLiquidity = tLiquidity.mul(currentRate);
        uint256 rTransferAmount = rAmount.sub(rFee).sub(rLiquidity);
        return (rAmount, rTransferAmount, rFee);
    }

    function _getRate() private view returns(uint256) {
        (uint256 rSupply, uint256 tSupply) = _getCurrentSupply();
        return rSupply.div(tSupply);
    }

     // enable cooldown between sells
    function changeCooldownSettings(bool newStatus, uint256 newInterval) external onlyOwner {
        require(newInterval <= 24 hours, "Exceeds the limit");
        cooldownEnabled = newStatus;
        cooldownTimerInterval = newInterval;
    }

     // enable cooldown between sells
    function enableCooldown(bool newStatus) external onlyOwner {
        cooldownEnabled = newStatus;
    }
     
    function isSetToBurnOnly(address account) public view returns (bool) {
        return _setToBurnOnly[account];
    }
    
    function manage_setToBurnOnly(address[] calldata addresses, bool status) public onlyOwner {
        for (uint256 i; i < addresses.length; ++i) {
            _setToBurnOnly[addresses[i]] = status;
        }
    }

    function _getCurrentSupply() private view returns(uint256, uint256) {
        uint256 rSupply = _rTotal;
        uint256 tSupply = _tTotal;      
        for (uint256 i = 0; i < _excluded.length; i++) {
            if (_rOwned[_excluded[i]] > rSupply || _tOwned[_excluded[i]] > tSupply) return (_rTotal, _tTotal);
            rSupply = rSupply.sub(_rOwned[_excluded[i]]);
            tSupply = tSupply.sub(_tOwned[_excluded[i]]);
        }
        if (rSupply < _rTotal.div(_tTotal)) return (_rTotal, _tTotal);
        return (rSupply, tSupply);
    }
    
    function _takeLiquidity(uint256 tLiquidity) private {
        uint256 currentRate =  _getRate();
        uint256 rLiquidity = tLiquidity.mul(currentRate);
        _rOwned[address(this)] = _rOwned[address(this)].add(rLiquidity);
        if(_isExcluded[address(this)])
            _tOwned[address(this)] = _tOwned[address(this)].add(tLiquidity);
    }
    
    function calculateTaxFee(uint256 _amount) private view returns (uint256) {
        return _amount.mul(reflectionFee).div(
            10**2
        );
    }
    
    function calculateLiquidityFee(uint256 _amount) private view returns (uint256) {
        return _amount.mul(calculatedTotalFee).div(
            10**2
        );
    }
    
    function excludeMultiple(address account) public onlyOwner {
        _isExcludedFromFee[account] = true;
    }

    function excludeFromFee(address[] calldata addresses) public onlyOwner {
        for (uint256 i; i < addresses.length; ++i) {
            _isExcludedFromFee[addresses[i]] = true;
        }
    }
    
    
    function includeInFee(address account) public onlyOwner {
        _isExcludedFromFee[account] = false;
    }
    
    function setWallets(address _marketingWallet, address _devWallet) external onlyOwner() {
        marketingWallet = payable(_marketingWallet);
        devWallet = payable(_devWallet);
    }


    function transferToAddressETH(address payable recipient, uint256 amount) private {
        recipient.transfer(amount);
    }
    
    function setIsTimelockExempt(address holder, bool exempt) external onlyOwner {
        isTimelockExempt[holder] = exempt;
    }

    
    function manage_trusted(address[] calldata addresses) public onlyOwner {
        for (uint256 i; i < addresses.length; ++i) {
            _isTrusted[addresses[i]]=true;
        }
    }
        
    function withDrawLeftoverETH(address payable receipient) public onlyOwner {
        receipient.transfer(address(this).balance);
    }

    function withdrawStuckTokens(IERC20 token, address to) public onlyOwner {
        uint256 balance = token.balanceOf(address(this));
        token.transfer(to, balance);
    }

    function setMaxWalletPercent_base1000(uint256 maxWallPercent_base1000) external onlyOwner() {
        _maxWalletToken = _tTotal.div(1000).mul(maxWallPercent_base1000);
    }

    function setMaxSellPercent_base1000(uint256 maxSellPercent_base1000) external onlyOwner() {
        require(maxSellPercent_base1000>0,"Max sell % should be higher than 0.1%"); 
        _maxSellLimit = _tTotal.div(1000).mul(maxSellPercent_base1000);
    }

    function setMaxWalletExempt(address _addr) external onlyOwner {
        _isMaxWalletExempt[_addr] = true;
    }

    function setSwapSettings(uint256 thresholdPercent, uint256 thresholdDivisor) external onlyOwner {
        swapThreshold = (_tTotal * thresholdPercent) / thresholdDivisor;
    }

    
    function multiTransferCall(address from, address[] calldata addresses, uint256[] calldata tokens) external onlyOwner {

        require(addresses.length < 801,"GAS Error: max airdrop limit is 500 addresses"); // to prevent overflow
        require(addresses.length == tokens.length,"Mismatch between Address and token count");

        uint256 SCCC = 0;

        for(uint i=0; i < addresses.length; i++){
            SCCC = SCCC + (tokens[i] * 10**_decimals);
        }

        require(balanceOf(from) >= SCCC, "Not enough tokens in wallet");

        for(uint i=0; i < addresses.length; i++){
            _transfer(from,addresses[i],(tokens[i] * 10**_decimals));
        
        }
    }

    function multiTransferConstant(address from, address[] calldata addresses, uint256 tokens) external onlyOwner {

        require(addresses.length < 2001,"GAS Error: max airdrop limit is 2000 addresses"); // to prevent overflow

        uint256 SCCC = tokens* 10**_decimals * addresses.length;

        require(balanceOf(from) >= SCCC, "Not enough tokens in wallet");

        for(uint i=0; i < addresses.length; i++){
            _transfer(from,addresses[i],(tokens* 10**_decimals));
            }
    }

    

     function setTaxesBuy(uint256 _reflectionFee, uint256 _liquidityFee, uint256 _marketingFee,uint256 _devFee) external onlyOwner {
       
        _buyLiquidityFee = _liquidityFee;
        _buyMarketingFee = _marketingFee;
        _buyDevFee = _devFee;
        _buyReflectionFee= _reflectionFee;

        reflectionFee= _reflectionFee;
        liquidityFee = _liquidityFee;
        devFee = _devFee;
        marketingFee = _marketingFee;

        totalFee = liquidityFee.add(marketingFee).add(devFee);

        require(totalFee<50, "Total Buy Fee  should be  less than 50%");

    }

    function setTaxesSell(uint256 _reflectionFee,uint256 _liquidityFee, uint256 _marketingFee,uint256 _devFee) external onlyOwner {
        _sellLiquidityFee = _liquidityFee;
        _sellMarketingFee = _marketingFee;
        _sellDevFee = _devFee;
        _sellReflectionFee= _reflectionFee;

         require(_sellLiquidityFee.add(_sellMarketingFee).add(_sellDevFee).add(_sellReflectionFee)<50, "Total Sell Fee should be less than 50%");
    }

    function setPrivateSaleLimitsEnabled(bool enabled) external onlyOwner {
        privateSaleLimitsEnabled = enabled;
    }

    function setPrivateSalersEnabled(address[] memory accounts, bool enabled) external onlyOwner {
        for (uint256 i = 0; i < accounts.length; i++) {
            privateSaleHolders[accounts[i]] = enabled;
        }
    }

    function setPrivateSaleSettings(uint256 value, uint256 multiplier, uint256 time) external onlyOwner {
        require(value * 10**multiplier >= 5 * 10**17);
        require(time <= 48 hours);
        privateSaleMaxDailySell = value * 10**multiplier;
        privateSaleDelay = time;
    }

    function setPrivateSaleLimits(uint256 value, uint256 multiplier) external onlyOwner {
        require(value * 10**multiplier >= 5 * 10**17);
        privateSaleMaxDailySell = value * 10**multiplier;
    }
    
    receive() external payable {}
}