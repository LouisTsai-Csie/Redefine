---
title: BlazCTF 2024 Tutori4l
date: 2024-09-25 16:48:17
tags:
---

### Introduction

Hi, this is my second article for the BlazCTF 2024 challenge writeup, and today I will breakdown the `Tutori4l` challenge. It is under `Solidity` and `DeFi` category and related to Uniswap V4. There are 21 teams solved this challenge during the contest.

BlazCTF 2024 Tutori4l Challenge Link: https://github.com/fuzzland/blazctf-2024/tree/main/tutori4l

As usual, let's first check out the deployment script to understand the environment setting for this challenge.

### Overview

There are several addresses in the deployment script: `player`, `PoolManager` and `challenge `, after the setting, both the `player` and `challenge` account will have 1 ether.

What is `PoolManager`? It is part of the Uniswap V4 contract that manages the pool states, which we will interact with for token swap or providing liquidity.

In the old Uniswap architecture, each pool is deployed by the factory contract, meaning there is an individual smart contract for each pool. This design makes certain operations more gas-consuming, such as creating a new pool or performing a multi-hop swap.

For example, in Uniswap v2, if we want to swap a token along the path A - B - C - D, the user must first transfer their A tokens to the (A, B) Uniswap pair. The (A, B) pool will then transfer B tokens to the user, after which the user transfers B tokens to the (B, C) pool, and so on, until they finally receive the desired D tokens. This process involves 6 token transfers, consuming a significant amount of gas. While a router can simplify the process, it still requires several token transfer operations.

Uniswap v2 router implementation: https://github.com/Uniswap/v2-periphery/blob/0335e8f7e1bd1e8d8329fd300aea2ef2f36dd19f/contracts/UniswapV2Router02.sol#L212

In Uniswap v4, a pool manager contract uses a mapping state variable to track each unique pool. All pool states are stored within the `PoolManager` contract, instead of storing in the individual pool contracts.

Let's move on to the `Challenge` contract, it has four immutable variable, `player` and `manager` is configured by the variable in the constructor, the `token` is created by the `challenge` contract. The interesting things here is the `hook` contract creation:

```C
uint160 flags = uint160(Hooks.BEFORE_SWAP_FLAG | Hooks.AFTER_SWAP_FLAG);
(address hookAddress, bytes32 salt) =
    HookMiner.find(address(this), flags, type(Hook).creationCode, abi.encode(address(manager)));
hook = new Hook{salt: salt}(manager);
assert(hookAddress == address(hook));
```

Why do we need the `flag` value? In the Uniswap v4 architecture, there are multiple hook functions, and the pool manager uses the address of the hook contract to determine which callback functions it implements.

Each hook function is associated with a specific flag, which you can learn more about here:

```
uint160 internal constant ALL_HOOK_MASK = uint160((1 << 14) - 1);

uint160 internal constant BEFORE_INITIALIZE_FLAG = 1 << 13;
uint160 internal constant AFTER_INITIALIZE_FLAG = 1 << 12;

uint160 internal constant BEFORE_ADD_LIQUIDITY_FLAG = 1 << 11;
uint160 internal constant AFTER_ADD_LIQUIDITY_FLAG = 1 << 10;

uint160 internal constant BEFORE_REMOVE_LIQUIDITY_FLAG = 1 << 9;
uint160 internal constant AFTER_REMOVE_LIQUIDITY_FLAG = 1 << 8;

uint160 internal constant BEFORE_SWAP_FLAG = 1 << 7;
uint160 internal constant AFTER_SWAP_FLAG = 1 << 6;

uint160 internal constant BEFORE_DONATE_FLAG = 1 << 5;
uint160 internal constant AFTER_DONATE_FLAG = 1 << 4;

uint160 internal constant BEFORE_SWAP_RETURNS_DELTA_FLAG = 1 << 3;
uint160 internal constant AFTER_SWAP_RETURNS_DELTA_FLAG = 1 << 2;
uint160 internal constant AFTER_ADD_LIQUIDITY_RETURNS_DELTA_FLAG = 1 << 1;
uint160 internal constant AFTER_REMOVE_LIQUIDITY_RETURNS_DELTA_FLAG = 1 << 0;
```

Reference: https://github.com/Uniswap/v4-core/blob/main/src/libraries/Hooks.sol

These flags correspond to specific bits in the address of the hook smart contract. The value of each bit (0 or 1) indicates whether a particular flag is set to true or false.

For example, in our challenge, the `Hook` contract implements two hook functions: `afterSwap` and `beforeSwap` (as seen in `Hook::getHookPermissions`). This means the bitmask of the Hook contract will have the 6th and 7th bits set to 1.

The HookMinter contract is designed to find an address that follows the rules mentioned above. It attempts to generate a salt that produces a hook address with the desired flags.

After the hook is created, it's time to create the pool. In the Uniswap v4 design, each pool has its own unique pool ID, which is the hash of the PoolKey structure. The PoolKey contains five fields: currency0, currency1, fee, tickSpacing, and hooks.

Uniswap v4 uses the same concentrated liquidity mechanism as in Uniswap v3, and here is for you to define the `tickSpacing` value, while `currency0` and `currency1` fields represent the token pair for the pool.

It then initialize the pool through the pool manager, passing the `PoolKey`, a starting price, and a data field as parameter.

The starting price is represented by the Q-notation, it represents the 

### Change