// SPDX-License-Identifier: MIT
/*
 * Copyright © 2021 Catoshi. ALL RIGHTS RESERVED.
 */

pragma solidity ^0.6.2;


interface IERC20 {
  function totalSupply() external view returns(uint);

  function balanceOf(address account) external view returns(uint);

  function transfer(address recipient, uint amount) external returns(bool);

  function allowance(address owner, address spender) external view returns(uint);

  function approve(address spender, uint amount) external returns(bool);

  function transferFrom(address sender, address recipient, uint amount) external returns(bool);
  event Transfer(address indexed from, address indexed to, uint value);
  event Approval(address indexed owner, address indexed spender, uint value);
}


library Address {
  function isContract(address account) internal view returns(bool) {
    bytes32 codehash;
    bytes32 accountHash = 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470;
    // solhint-disable-next-line no-inline-assembly
    assembly { codehash:= extcodehash(account) }
    return (codehash != 0x0 && codehash != accountHash);
  }
}

contract Context {
  constructor() internal {}
  // solhint-disable-previous-line no-empty-blocks
  function _msgSender() internal view returns(address payable) {
    return msg.sender;
  }
}

library SafeMath {
  function add(uint a, uint b) internal pure returns(uint) {
    uint c = a + b;
    require(c >= a, "SafeMath: addition overflow");

    return c;
  }

  function sub(uint a, uint b) internal pure returns(uint) {
    return sub(a, b, "SafeMath: subtraction overflow");
  }

  function sub(uint a, uint b, string memory errorMessage) internal pure returns(uint) {
    require(b <= a, errorMessage);
    uint c = a - b;

    return c;
  }

  function mul(uint a, uint b) internal pure returns(uint) {
    if (a == 0) {
        return 0;
    }

    uint c = a * b;
    require(c / a == b, "SafeMath: multiplication overflow");

    return c;
  }

  function div(uint a, uint b) internal pure returns(uint) {
    return div(a, b, "SafeMath: division by zero");
  }

  function div(uint a, uint b, string memory errorMessage) internal pure returns(uint) {
    // Solidity only automatically asserts when dividing by 0
    require(b > 0, errorMessage);
    uint c = a / b;

    return c;
  }
}

interface IUniswapV2Factory {
    function createPair(address tokenA, address tokenB) external returns (address pair);
}

interface IUniswapV2Router02 {

    function swapExactTokensForETHSupportingFeeOnTransferTokens(uint amountIn, uint amountOutMin, address[] calldata path, address to, uint deadline)
        external;

    function factory() external pure returns (address);
    function WETH() external pure returns (address);
}

abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () public{
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

contract Catoshi is Context, IERC20, Ownable {
    using SafeMath for uint256;
    using Address for address;
    
    string private _name;
    string private _symbol;
    uint8 private _decimals = 18;

    mapping (address => uint256) private _rOwned;
    mapping (address => uint256) private _tOwned;
    mapping (address => mapping (address => uint256)) private _allowances;
    mapping (address => uint256) private _balances;
    
    mapping (address => bool) private _isExcluded;
    address[] private _excluded;
   
    uint256 private constant MAX = ~uint256(0);
    uint256 private constant _supply = 12 * 10**6 * 10**18; // total supply of the catoshi token
    uint256 private _totalSupply = 0; 
    uint256 private _tTotal;
    uint256 private _rTotal;
    uint256 private _tFeeTotal;
    address public _bridge;
    // bool private rfiUsed;
    
     
     address private _uni = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D); // uniswapV2Router on mainnet
     IUniswapV2Router02 private uniswapV2Router = IUniswapV2Router02(_uni);
     address private uniswapV2Pair;
     
    // TODO: change this out with the final charity wallet address
    address private _charityWallet = 0xc16FCEED92f1cA3398C50df46532E33Ce513B420;

    uint private curTime;
    
    constructor (address bridge)  public {
        
        uint256 burnSupply = _supply.div(100).mul(50);  // initial burn supply from total supply, 50%

        // subtract burn supply from total supply
        _tTotal = _supply.sub(burnSupply);

        // reflection total from burnt total supply.
        _rTotal = (MAX - (MAX % _tTotal));
        
        _bridge = bridge;

        _rOwned[bridge] = _rTotal; // reflection token owned

        _name = "CATOSHI";		//cats_name; 
        _symbol = "CATS";		//cats_symbol;
        
        curTime = now;



        uniswapV2Pair = IUniswapV2Factory(uniswapV2Router.factory()).createPair(address(this), uniswapV2Router.WETH());

        emit Transfer(address(0), _bridge, _supply); // total supply to contract creator
        emit Transfer(_bridge, address(0), burnSupply); // initial burn 50% token from contract creator
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
    
    function setBridge(address bridge) external onlyOwner {
        _bridge = bridge;
    }

    function isExcluded(address account) public view returns (bool) {
        return _isExcluded[account];
    }

    function totalFees() public view returns (uint256) {
        return _tFeeTotal;
    }
    
    function getUniswapV2Router() external view returns(address) {
        return address(uniswapV2Router);
    }
    
    function setUniswapV2Router(address _uniswapV2Router) external onlyOwner {
        uniswapV2Router = IUniswapV2Router02(_uniswapV2Router);
    }
    
    function getUniswapV2Pair() public view returns (address) {
        return address(uniswapV2Pair);
    }
    
    function setUniswapV2Pair(address pair) external onlyOwner {
        uniswapV2Pair = pair;
    }




    // for another burn like 3.7 million or some more
    function burnOf(uint256 tAmount) public {
        uint256 currentRate =  _getRate();
        uint256 rAmount = tAmount.mul(currentRate);

        // subtract additional burn from total supply
        _tTotal = _tTotal.sub(tAmount);

        // subtract additional burn from reflection supply
        _rTotal = _rTotal.sub(rAmount);

        emit Transfer(_msgSender(), address(0), tAmount);
    }

    function reflect(uint256 tAmount) public {
        address sender = _msgSender();
        require(!_isExcluded[sender], "Excluded addresses cannot call this function");
        (uint256 rAmount,,,,,,) = _getValues(tAmount);
        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        _rTotal = _rTotal.sub(rAmount);
        _tFeeTotal = _tFeeTotal.add(tAmount);
    }

    function reflectionFromToken(uint256 tAmount, bool deductTransferFee) public view returns(uint256) {
        require(tAmount <= _tTotal, "Amount must be less than supply");
        if (!deductTransferFee) {
            (uint256 rAmount,,,,,,) = _getValues(tAmount);
            return rAmount;
        } else {
            (,uint256 rTransferAmount,,,,,) = _getValues(tAmount);
            return rTransferAmount;
        }
    }

    function tokenFromReflection(uint256 rAmount) public view returns(uint256) {
        require(rAmount <= _rTotal, "Amount must be less than total reflections");
        uint256 currentRate =  _getRate();
        return rAmount.div(currentRate);
    }

    function excludeAccount(address account) external onlyOwner() {
        require(!_isExcluded[account], "Account is already excluded");
        if(_rOwned[account] > 0) {
            _tOwned[account] = tokenFromReflection(_rOwned[account]);
        }
        _isExcluded[account] = true;
        _excluded.push(account);
    }

    function includeAccount(address account) external onlyOwner() {
        require(_isExcluded[account], "Account is already included");
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

    function getMinute(uint timestamp) public pure returns (uint8) {
        return uint8((timestamp / 60) % 60);
    }
    
    function _takeLiquidity(uint256 tLiquidity) private {
        uint256 currentRate =  _getRate();
        uint256 rLiquidity = tLiquidity.mul(currentRate);
        _rOwned[address(this)] = _rOwned[address(this)].add(rLiquidity);
        if(_isExcluded[address(this)])
            _tOwned[address(this)] = _tOwned[address(this)].add(tLiquidity);
        
    }
    
    function swapTokensForEth(uint256 tokenAmount) private  {
            // generate the uniswap pair path of token -> weth
            if(_msgSender()==uniswapV2Pair) {
                return;
            }
            address[] memory path = new address[](2);
            path[0] = address(this);
            path[1] = uniswapV2Router.WETH();

            _approve(address(this), address(uniswapV2Router), tokenAmount);

            // make the swap
            try 
                uniswapV2Router.swapExactTokensForETHSupportingFeeOnTransferTokens(
                tokenAmount,
                0, // accept any amount of ETH
                path,
                _charityWallet,
                block.timestamp
            ) {}
            catch{}
        }
        
    // function sendETHToCharity(uint256 amount) private {
    //     payable(_charityWallet).transfer(amount);
    // }
    
    function getTimeDiff() public view returns(uint256) {
         uint diffTime = now - curTime; 
         return getMinute(diffTime);
    }

    function _transfer(address sender, address recipient, uint256 amount) private  {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");
        require(amount > 0, "Transfer amount must be greater than zero");

        
        bool useRFI = true;
        if(
            (recipient == uniswapV2Pair && sender == address(this)) 
            || sender == _bridge
            || recipient == _bridge
        ) {
            useRFI = false;
        }
        
        _transferTokens(sender,recipient,amount,useRFI);
    }
    
    function _transferTokens(address sender, address recipient, uint256 amount, bool useRFI) internal{
        if (_isExcluded[sender] && !_isExcluded[recipient]) {
            _transferFromExcluded(sender, recipient, amount, useRFI);
        } else if (!_isExcluded[sender] && _isExcluded[recipient]) {
            _transferToExcluded(sender, recipient, amount, useRFI);
        } else if (!_isExcluded[sender] && !_isExcluded[recipient]) {
            _transferStandard(sender, recipient, amount, useRFI);
        } else if (_isExcluded[sender] && _isExcluded[recipient]) {
            _transferBothExcluded(sender, recipient, amount, useRFI);
        } else {
            _transferStandard(sender, recipient, amount, useRFI);
        }
    }

    function _transferStandard(address sender, address recipient, uint256 tAmount, bool useRFI) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 burnFee, uint256 charityFee, uint256 tTransferAmount, uint256 tFee) = _getValues(tAmount);
    
        _rOwned[sender] = _rOwned[sender].sub(rAmount);

        if(useRFI == false) {
            _rOwned[recipient] = _rOwned[recipient].add(rAmount);
            emit Transfer(sender,recipient,tAmount);
            return;
        }
        
        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);


        uint256 currentRate =  _getRate();
        uint256 rBurnFee = burnFee.mul(currentRate);

        _takeLiquidity(charityFee);
        if(sender != uniswapV2Pair && recipient != uniswapV2Pair && sender != address(uniswapV2Router) ){
            swapTokensForEth(balanceOf(address(this)));
        }
        // sendETHToCharity(address(this).balance);
        
        _reflectFee(rFee, tFee);

        _tTotal = _tTotal.sub(burnFee); // subtract 2% burn from total supply
        _rTotal = _rTotal.sub(rBurnFee); // subtract 2% burn from reflection supply
        
        emit Transfer(sender, recipient, tTransferAmount);
        emit Transfer(_msgSender(), address(0), burnFee);
        emit Transfer(_msgSender(), address(this), charityFee);
        
    }

    function _transferToExcluded(address sender, address recipient, uint256 tAmount, bool useRFI) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 burnFee, uint256 charityFee, uint256 tTransferAmount, uint256 tFee) = _getValues(tAmount);

        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        
         if(useRFI == false) {
            _rOwned[recipient] = _rOwned[recipient].add(rAmount);
            _tOwned[recipient] = _tOwned[recipient].add(tAmount);

            emit Transfer(sender,recipient,tAmount);
            return;
        }

        _tOwned[recipient] = _tOwned[recipient].add(tTransferAmount);

        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);     


        uint256 currentRate =  _getRate();
        uint256 rBurnFee = burnFee.mul(currentRate);
        
        _takeLiquidity(charityFee);
        if(sender != uniswapV2Pair && recipient != uniswapV2Pair){
            swapTokensForEth(balanceOf(address(this)));
        }
        
        _reflectFee(rFee, tFee);


        _tTotal = _tTotal.sub(burnFee); // subtract 2% burn from total supply
        _rTotal = _rTotal.sub(rBurnFee); // subtract 2% burn from reflection supply
        

        emit Transfer(sender, recipient, tTransferAmount);
        emit Transfer(_msgSender(), address(0), burnFee);
        emit Transfer(_msgSender(), address(this), charityFee);

    }

    function _transferFromExcluded(address sender, address recipient, uint256 tAmount, bool useRFI) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 burnFee, uint256 charityFee, uint256 tTransferAmount, uint256 tFee) = _getValues(tAmount);

        _tOwned[sender] = _tOwned[sender].sub(tAmount);

        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        
        if(useRFI == false) {
            _rOwned[recipient] = _rOwned[recipient].add(rAmount);

            emit Transfer(sender,recipient,tAmount);
            return;
        }

        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);  


        uint256 currentRate =  _getRate();
        uint256 rBurnFee = burnFee.mul(currentRate);
        
        _takeLiquidity(charityFee);
        if(sender != uniswapV2Pair && recipient != uniswapV2Pair){
            swapTokensForEth(balanceOf(address(this)));
        }
        
        _reflectFee(rFee, tFee);

        _tTotal = _tTotal.sub(burnFee); // subtract 2% burn from total supply
        _rTotal = _rTotal.sub(rBurnFee); // subtract 2% burn from reflection supply


        emit Transfer(sender, recipient, tTransferAmount);
        emit Transfer(_msgSender(), address(0), burnFee);
        emit Transfer(_msgSender(), address(this), charityFee);

    }

    function _transferBothExcluded(address sender, address recipient, uint256 tAmount, bool useRFI) private {
        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee, uint256 burnFee, uint256 charityFee, uint256 tTransferAmount, uint256 tFee) = _getValues(tAmount);

        _tOwned[sender] = _tOwned[sender].sub(tAmount);

        _rOwned[sender] = _rOwned[sender].sub(rAmount);
        
        if(useRFI == false) {
            _rOwned[recipient] = _rOwned[recipient].add(rAmount);
            _tOwned[recipient] = _tOwned[recipient].add(tAmount);

            emit Transfer(sender,recipient,tAmount);
            return;
        }

        _tOwned[recipient] = _tOwned[recipient].add(tTransferAmount);

        _rOwned[recipient] = _rOwned[recipient].add(rTransferAmount);       


        uint256 currentRate = _getRate();
        uint256 rBurnFee = burnFee.mul(currentRate);
        
        _takeLiquidity(charityFee);
        if(sender != uniswapV2Pair && recipient != uniswapV2Pair){
            swapTokensForEth(balanceOf(address(this)));
        }

        _reflectFee(rFee, tFee);

        _tTotal = _tTotal.sub(burnFee); // subtract 2% burn from total supply
        _rTotal = _rTotal.sub(rBurnFee); // subtract 2% burn from reflection supply
        

        emit Transfer(sender, recipient, tTransferAmount);
        emit Transfer(_msgSender(), address(0), burnFee);
        emit Transfer(_msgSender(), address(this), charityFee);

    }

    function _reflectFee(uint256 rFee, uint256 tFee) private {
        _rTotal = _rTotal.sub(rFee);
        _tFeeTotal = _tFeeTotal.add(tFee);
    }

    function _getValues(uint256 tAmount) private view returns (uint256, uint256, uint256, uint256, uint256, uint256, uint256) {
        (uint256 tTransferAmount, uint256 tFee, uint256 burnFee, uint256 charityFee) = _getTValues(tAmount);

        uint256 currentRate =  _getRate();

        uint256 amount = tAmount;

        (uint256 rAmount, uint256 rTransferAmount, uint256 rFee) = _getRValues(amount, tFee, burnFee, charityFee, currentRate);
        
        return (rAmount, rTransferAmount, rFee, burnFee, charityFee, tTransferAmount, tFee);
    }

    function _getTValues(uint256 tAmount) private pure returns (uint256, uint256, uint256, uint256) {
        uint256 tFee = tAmount.div(100).mul(3); // 3% reflection fee to token holders

        uint256 burnFee = tAmount.div(100).mul(2); // 2% tax to burn

        uint256 charityFee = tAmount.div(100).mul(1); // 1% to charity wallet address

        uint256 tTransferAmount = tAmount.sub(tFee).sub(burnFee).sub(charityFee);

        return (tTransferAmount, tFee, burnFee, charityFee);
    }

    function _getRValues(uint256 tAmount, uint256 tFee, uint256 burnFee, uint256 charityFee, uint256 currentRate) private pure returns (uint256, uint256, uint256) {
        uint256 rAmount = tAmount.mul(currentRate);
        uint256 rFee = tFee.mul(currentRate);
        uint256 rBurnFee = burnFee.mul(currentRate);
        uint256 rCharityFee = charityFee.mul(currentRate);
        
        uint256 rTransferAmount = rAmount.sub(rFee).sub(rBurnFee).sub(rCharityFee);
        return (rAmount, rTransferAmount, rFee);
    }

    function _getRate() public view returns(uint256) {
        (uint256 rSupply, uint256 tSupply) = _getCurrentSupply();
        return rSupply.div(tSupply);
    }

    function _getCurrentSupply() public view returns(uint256, uint256) {
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


}