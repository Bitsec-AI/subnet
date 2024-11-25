## Samples

These codebase samples are the basis for the synthetic challenges in the subnet.

Contains 3 folders:

- clean codebases
  - 1 text file per codebase. may contain multiple files.
- vulnerable codebases
  - 2 files per codebase. 1 file is the contract, the other is the vulnerability.
- vulnerabilities
  - 1 file per vulnerability.

Approach 1: Analyze the codebases as is.

Approach 2: Analyze the codebases with the vulnerabilities injected.

To prep files for analysis:

- forge build

```bash
forge build --contracts samples/nft-reentrancy.sol
```
