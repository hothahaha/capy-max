// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IStrategyEngine {
    struct EngineInitParams {
        address wbtc;
        address usdc;
        address aavePool;
        address aaveOracle;
        address aaveProtocolDataProvider;
        address cpToken;
        address vault;
        address safeWallet;
    }
}
