// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {StrategyLib} from "../libraries/StrategyLib.sol";

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

    struct EmergencyWithdrawalInfo {
        address user;
        uint256 amount;
    }

    event Deposited(
        bytes32 indexed depositId,
        address indexed user,
        StrategyLib.TokenType tokenType,
        uint256 amount,
        uint256 borrowAmount,
        uint256 timestamp
    );

    event Withdrawn(address indexed user, uint256 amount, uint256 rewards);
    event EmergencyAction(address indexed user, uint256 amount);
    event PlatformFeeUpdated(uint256 oldFee, uint256 newFee);
    event BorrowCapacityUpdated(
        address indexed user,
        uint256 wbtcAmount,
        uint256 originalBorrowAmount,
        uint256 newBorrowAmount,
        uint256 difference,
        bool isIncrease,
        uint256 timestamp,
        uint256 healthFactor
    );

    function emergencyWbtcWithdrawal(
        EmergencyWithdrawalInfo[] calldata withdrawalInfos
    ) external returns (uint256[] memory amounts);
}
