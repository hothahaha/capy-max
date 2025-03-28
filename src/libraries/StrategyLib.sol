// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAaveOracle} from "../interfaces/aave/IAaveOracle.sol";
import {IPoolDataProvider} from "../interfaces/aave/IAaveProtocolDataProvider.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ICpToken} from "../interfaces/ICpToken.sol";
import {console} from "forge-std/console.sol";
import {IAavePool} from "../interfaces/aave/IAavePool.sol";
import {UserPosition} from "../UserPosition.sol";

/**
 * @title StrategyLib
 * @notice Library of functions to reduce the size of the StrategyEngine contract
 */
library StrategyLib {
    using SafeERC20 for IERC20;

    enum TokenType {
        WBTC,
        USDC
    }

    // Constants
    uint256 private constant BASIS_POINTS = 10000; // 100%

    // Events
    event TransferToVault(uint256 amount);

    /**
     * @notice Transfers USDC from one address to another
     * @param usdc The USDC token contract
     * @param from The source address
     * @param to The destination address
     * @param amount The amount to transfer
     */
    function transferUsdc(IERC20 usdc, address from, address to, uint256 amount) internal {
        if (from == address(this)) {
            usdc.safeTransfer(to, amount);
        } else {
            usdc.safeTransferFrom(from, to, amount);
        }
    }

    /**
     * @notice Calculates how much a user can borrow based on their collateral
     * @param aaveOracle The Aave oracle contract to get price data
     * @param usdc The USDC token contract address
     * @param totalCollateralBase User's total collateral in base units
     * @param defaultLiquidationThreshold The default liquidation threshold
     * @return borrowAmount The amount user can borrow
     */
    function calculateBorrowAmount(
        IAaveOracle aaveOracle,
        address usdc,
        uint256 totalDebtBase,
        uint256 totalCollateralBase,
        uint256 currentLiquidationThreshold,
        uint256 defaultLiquidationThreshold
    ) internal view returns (uint256) {
        if (totalCollateralBase == 0) {
            return 0; // Return 0 instead of reverting for library function
        }

        // ((totalCollateralBase * BASIS_POINTS) / ltv) -- availableBorrowBase
        // availableBorrowBase * currentLiquidationThreshold / defaultLiquidationThreshold -- maxBorrowIn
        // maxBorrowIn - totalDebtBase -- currentBorrowAmount
        uint256 availableBorrowBase = (totalCollateralBase * currentLiquidationThreshold) /
            (defaultLiquidationThreshold * 10 ** 2);
        if (availableBorrowBase < totalDebtBase) {
            return 0;
        }
        uint256 maxBorrowIn = availableBorrowBase - totalDebtBase;

        uint256 usdcPrice = aaveOracle.getAssetPrice(usdc);
        uint256 borrowAmount = (maxBorrowIn * 10 ** IERC20Metadata(usdc).decimals()) / usdcPrice;

        return borrowAmount;
    }

    /**
     * @notice Calculate the amount needed to repay a debt
     * @param asset The asset address
     * @param user The user address
     * @param dataProvider The Aave protocol data provider
     * @return The current variable debt to be repaid
     */
    function calculateRepayAmount(
        address asset,
        address user,
        IPoolDataProvider dataProvider
    ) internal view returns (uint256) {
        (, , uint256 currentVariableDebt, , , , , , ) = dataProvider.getUserReserveData(
            asset,
            user
        );
        return currentVariableDebt;
    }

    /**
     * @notice Generates a unique deposit ID
     * @param user User address
     * @param tokenType Type of token deposited
     * @param amount Amount deposited
     * @param timestamp Timestamp of deposit
     * @return depositId The unique deposit ID
     */
    function generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, tokenType, amount, timestamp));
    }

    /**
     * @notice Handles profit distribution including platform fees
     * @param totalProfit The profit amount
     * @param platformFeePercentage The platform fee percentage
     * @param usdc The USDC token contract
     * @param vault The vault address to send platform fees
     * @return userProfit The user's portion of profit
     */
    function handleProfit(
        uint256 totalProfit,
        uint256 platformFeePercentage,
        IERC20 usdc,
        address vault,
        ICpToken /* cpToken */,
        address /* recipient */
    ) internal returns (uint256 userProfit) {
        if (totalProfit <= 0) return 0;

        // Calculate platform fee
        uint256 platformFee = (totalProfit * platformFeePercentage) / BASIS_POINTS;
        userProfit = totalProfit - platformFee;

        // Store platform fee in vault
        if (platformFee > 0) {
            transferUsdc(usdc, address(this), vault, platformFee);
            emit TransferToVault(platformFee);
        }

        // Mint reward token
        // cpToken.mint(recipient, userProfit);

        return userProfit;
    }

    function handleWbtcWithdrawal(
        IERC20 usdc,
        IERC20 wbtc,
        address user,
        uint256 amount,
        uint256 totalWbtcAmount,
        address userPosition,
        IPoolDataProvider aaveProtocolDataProvider,
        IAavePool aavePool
    ) internal returns (uint256 amountUsdcAfterRepay, uint256 repayedAmount) {
        amountUsdcAfterRepay = amount;

        if (totalWbtcAmount > 0) {
            // Calculate amount to repay to Aave
            uint256 needRepayAmount = calculateRepayAmount(
                address(usdc),
                userPosition,
                aaveProtocolDataProvider
            );

            // Repay to Aave
            usdc.approve(address(aavePool), needRepayAmount);
            repayedAmount = UserPosition(payable(userPosition)).executeRepay(
                address(aavePool),
                address(usdc),
                needRepayAmount,
                2
            );

            if (needRepayAmount > amount) {
                revert("WithdrawalNeedRepayAmountLess");
            }

            // Withdraw WBTC from Aave
            uint256 withdrawnAmount = UserPosition(payable(userPosition)).executeAaveWithdraw(
                address(aavePool),
                address(wbtc),
                totalWbtcAmount,
                user
            );
            require(withdrawnAmount == totalWbtcAmount, "Withdrawal failed");

            // Update remaining USDC amount
            amountUsdcAfterRepay = amount - repayedAmount;
        }
    }

    function handleUsdcWithdrawalAndProfit(
        IERC20 usdc,
        address user,
        uint256 amountUsdcAfterRepay,
        uint256 totalUsdcPrincipal,
        uint256 platformFeePercentage,
        address vault,
        ICpToken cpToken
    ) internal returns (uint256 userProfit) {
        uint256 availableUsdc = usdc.balanceOf(address(this));
        uint256 profit;

        if (totalUsdcPrincipal > 0) {
            profit = amountUsdcAfterRepay - totalUsdcPrincipal;
        } else {
            profit = amountUsdcAfterRepay;
        }

        userProfit = handleProfit(profit, platformFeePercentage, usdc, vault, cpToken, user);

        uint256 totalTransferAmount = totalUsdcPrincipal + userProfit;
        require(availableUsdc >= totalTransferAmount, "InsufficientContractBalance");

        usdc.safeTransfer(user, totalTransferAmount);
        return userProfit;
    }

    function executeRepay(
        IERC20 usdc,
        address userPosition,
        address aavePool,
        uint256 repayAmount
    ) internal returns (uint256) {
        usdc.approve(aavePool, repayAmount);
        return
            UserPosition(payable(userPosition)).executeRepay(
                address(aavePool),
                address(usdc),
                repayAmount,
                2
            );
    }

    function executeBorrow(
        IERC20 usdc,
        address userPosition,
        address aavePool,
        uint256 borrowAmount
    ) internal returns (uint256) {
        UserPosition(payable(userPosition)).executeBorrow(
            address(aavePool),
            address(usdc),
            borrowAmount,
            2, // Variable rate
            0 // referralCode
        );

        usdc.approve(address(this), borrowAmount);
        usdc.transferFrom(userPosition, address(this), borrowAmount);

        return borrowAmount;
    }
}
