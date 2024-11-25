https://medium.com/buildbear/most-common-vulnerabilities-in-solidity-in-deep-part-1-587cc7e99845

Even though Solidity 0.8.x has safety measures, the integer division is still a tricky part. If you divide 5 by 2, you may expect 2.5, but in Solidity you’ll get 2 (it dismisses the decimal and rounds down). So if you’re working with fractions, you want to handle them properly.

contract IncorrectCalculation {
uint256 public result;

// A function that might cause incorrect calculation error
function calculate(uint256 a, uint256 b) public {
result = a / b;
}
}

// calculation done correctly in Solidity 0.8.x with precision

```solidity
contract CorrectCalculation {
  uint256 public result;

  // A function that might cause incorrect calculation error
  function calculate(uint256 a, uint256 b, uint256 precision) public {
  result = (a * precision) / b;
  }
}
```
