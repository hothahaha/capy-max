// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAaveOracle} from "../interfaces/aave/IAaveOracle.sol";
import {IPoolDataProvider} from "../interfaces/aave/IAaveProtocolDataProvider.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {ICpToken} from "../interfaces/ICpToken.sol";

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
     * @param currentLiquidationThreshold User's liquidation threshold
     * @param defaultLiquidationThreshold The default liquidation threshold
     * @return borrowAmount The amount user can borrow
     */
    function calculateBorrowAmount(
        IAaveOracle aaveOracle,
        address usdc,
        uint256 totalCollateralBase,
        uint256 currentLiquidationThreshold,
        uint256 defaultLiquidationThreshold
    ) internal view returns (uint256) {
        if (totalCollateralBase == 0) {
            return 0; // Return 0 instead of reverting for library function
        }

        // totalCollateralBase * currentLiquidationThreshold / 1.56 = maxBorrowIn
        uint256 maxBorrowIn = (totalCollateralBase * currentLiquidationThreshold) /
            (defaultLiquidationThreshold * 10 ** 2);

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
     * @param profit The profit amount
     * @param withdrawUSDCAmount The USDC amount to withdraw
     * @param platformFeePercentage The platform fee percentage
     * @param usdc The USDC token contract
     * @param vault The vault address to send platform fees
     * @param cpToken The CP token contract for minting rewards
     * @param recipient The recipient of the profit
     * @return userProfit The user's portion of profit
     * @return totalWithdrawAmount The total amount to withdraw
     */
    function handleProfit(
        uint256 profit,
        uint256 withdrawUSDCAmount,
        uint256 platformFeePercentage,
        IERC20 usdc,
        address vault,
        ICpToken cpToken,
        address recipient
    ) internal returns (uint256 userProfit, uint256 totalWithdrawAmount) {
        if (profit <= 0) return (0, withdrawUSDCAmount);

        // Calculate platform fee
        uint256 platformFee = (profit * platformFeePercentage) / BASIS_POINTS;
        userProfit = profit - platformFee;

        // Store platform fee in vault
        if (platformFee > 0) {
            transferUsdc(usdc, address(this), vault, platformFee);
        }

        totalWithdrawAmount = withdrawUSDCAmount + userProfit;

        // Transfer user profit
        transferUsdc(usdc, address(this), recipient, totalWithdrawAmount);

        // Mint reward token
        cpToken.mint(recipient, userProfit);

        return (userProfit, totalWithdrawAmount);
    }
}
