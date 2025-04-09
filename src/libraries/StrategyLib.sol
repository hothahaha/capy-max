// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IAavePool} from "../interfaces/aave/IAavePool.sol";
import {IAaveOracle} from "../interfaces/aave/IAaveOracle.sol";
import {IPoolDataProvider} from "../interfaces/aave/IAaveProtocolDataProvider.sol";
import {ICpToken} from "../interfaces/ICpToken.sol";
import {UserPosition} from "../UserPosition.sol";

library StrategyLib {
    using SafeERC20 for IERC20;

    //--------------------------------------------------------------------------
    // Events
    //--------------------------------------------------------------------------
    event TransferToVault(uint256 amount);

    //--------------------------------------------------------------------------
    // Errors
    //--------------------------------------------------------------------------
    error StrategyLib__InvalidAmount();
    error StrategyLib__TransferFailed();
    error StrategyLib__InsufficientBalance();

    //--------------------------------------------------------------------------
    // Type declarations
    //--------------------------------------------------------------------------
    enum TokenType {
        WBTC,
        USDC
    }

    struct UserInfo {
        uint256 totalWbtcDeposited;
        uint256 totalUsdcDeposited;
        uint256 totalBorrowAmount;
        uint256 lastDepositTime;
        DepositRecord[] deposits;
    }

    struct DepositRecord {
        bytes32 depositId;
        TokenType tokenType;
        uint256 amount;
        uint256 timestamp;
        uint256 borrowAmount;
        bool isWithdrawn;
    }

    struct RepayState {
        uint256 principal;
        uint256 profit;
        bool hasRepaid;
    }

    struct RepayInfo {
        address user;
        uint256 amount;
    }

    //--------------------------------------------------------------------------
    // Core Functions
    //--------------------------------------------------------------------------

    /// @notice Calculate the amount of debt a user needs to repay
    /// @param asset The asset address (USDC)
    /// @param user The user address
    /// @param aaveProtocolDataProvider Aave protocol data provider contract
    /// @return The amount of debt to be repaid
    function calculateRepayAmount(
        address asset,
        address user,
        IPoolDataProvider aaveProtocolDataProvider
    ) public view returns (uint256) {
        (, , uint256 currentVariableDebt, , , , , , ) = aaveProtocolDataProvider.getUserReserveData(
            asset,
            user
        );
        return currentVariableDebt;
    }

    /// @notice Calculate the amount of USDC a user can borrow
    /// @param aaveOracle Aave oracle contract
    /// @param usdc USDC token address
    /// @param totalDebtBase Total debt base
    /// @param totalCollateralBase Total collateral base
    /// @param currentLiquidationThreshold Current liquidation threshold
    /// @param defaultLiquidationThreshold Default liquidation threshold
    /// @return The amount of USDC that can be borrowed
    function calculateBorrowAmount(
        IAaveOracle aaveOracle,
        address usdc,
        uint256 totalDebtBase,
        uint256 totalCollateralBase,
        uint256 currentLiquidationThreshold,
        uint256 defaultLiquidationThreshold
    ) public view returns (uint256) {
        if (totalCollateralBase == 0) {
            return 0;
        }

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

    /// @notice Transfer USDC tokens
    /// @param usdc USDC token contract
    /// @param from The address to transfer from
    /// @param to The address to transfer to
    /// @param amount The amount to transfer
    function transferUsdc(IERC20 usdc, address from, address to, uint256 amount) public {
        if (from == address(this)) {
            usdc.safeTransfer(to, amount);
        } else {
            usdc.safeTransferFrom(from, to, amount);
        }
    }

    /// @notice Handle profit distribution
    /// @param totalProfit Total profit
    /// @param platformFeePercentage Platform fee percentage
    /// @param usdc USDC token contract
    /// @param vault Vault address
    /// @return The profit received by the user
    function handleProfit(
        uint256 totalProfit,
        uint256 platformFeePercentage,
        IERC20 usdc,
        address vault,
        ICpToken /* cpToken */,
        address /* user */
    ) public returns (uint256) {
        if (totalProfit <= 0) return 0;

        // Calculate platform fee
        uint256 platformFee = (totalProfit * platformFeePercentage) / 10000;
        uint256 userProfit = totalProfit - platformFee;

        // Store platform fee in vault
        if (platformFee > 0) {
            transferUsdc(usdc, address(this), vault, platformFee);
            emit TransferToVault(platformFee);
        }

        // Mint reward token
        // cpToken.mint(recipient, userProfit);

        return userProfit;
    }

    /// @notice Handle WBTC withdrawal
    /// @param usdc USDC token contract
    /// @param wbtc WBTC token contract
    /// @param user User address
    /// @param amount Withdrawal amount
    /// @param totalWbtcAmount Total WBTC amount
    /// @param userPosition User position contract address
    /// @param aaveProtocolDataProvider Aave protocol data provider
    /// @param aavePool Aave pool contract
    /// @return amountUsdcAfterRepay Remaining USDC amount after repayment
    function handleWbtcWithdrawal(
        IERC20 usdc,
        IERC20 wbtc,
        address user,
        uint256 amount,
        uint256 totalWbtcAmount,
        address userPosition,
        IPoolDataProvider aaveProtocolDataProvider,
        IAavePool aavePool
    ) public returns (uint256 amountUsdcAfterRepay) {
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
            uint256 repayedAmount = UserPosition(payable(userPosition)).executeRepay(
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

    /// @notice Handle USDC withdrawal and profit distribution
    /// @param usdc USDC token contract
    /// @param user User address
    /// @param amountUsdcAfterRepay USDC amount after repayment
    /// @param totalUsdcAmount Total USDC amount
    /// @param platformFeePercentage Platform fee percentage
    /// @param vault Vault address
    /// @param cpToken CP token contract
    /// @return The profit received by the user
    function handleUsdcWithdrawalAndProfit(
        IERC20 usdc,
        address user,
        uint256 amountUsdcAfterRepay,
        uint256 totalUsdcAmount,
        uint256 platformFeePercentage,
        address vault,
        ICpToken cpToken
    ) public returns (uint256) {
        uint256 availableUsdc = usdc.balanceOf(address(this));
        uint256 profit;

        if (totalUsdcAmount > 0) {
            profit = amountUsdcAfterRepay - totalUsdcAmount;
        } else {
            profit = amountUsdcAfterRepay;
        }

        uint256 userProfit = handleProfit(
            profit,
            platformFeePercentage,
            usdc,
            vault,
            cpToken,
            user
        );

        uint256 totalTransferAmount = totalUsdcAmount + userProfit;
        require(availableUsdc >= totalTransferAmount, "InsufficientContractBalance");

        usdc.safeTransfer(user, totalTransferAmount);
        return userProfit;
    }

    /// @notice Execute repayment
    /// @param usdc USDC token contract
    /// @param userPosition User position contract address
    /// @param aavePool Aave pool contract address
    /// @param repayAmount Repayment amount
    /// @return The actual amount repaid
    function executeRepay(
        IERC20 usdc,
        address userPosition,
        address aavePool,
        uint256 repayAmount
    ) public returns (uint256) {
        usdc.approve(aavePool, repayAmount);
        return
            UserPosition(payable(userPosition)).executeRepay(
                address(aavePool),
                address(usdc),
                repayAmount,
                2
            );
    }

    /// @notice Execute borrowing
    /// @param usdc USDC token contract
    /// @param userPosition User position contract address
    /// @param aavePool Aave pool contract address
    /// @param borrowAmount Borrow amount
    /// @return The actual amount borrowed
    function executeBorrow(
        IERC20 usdc,
        address userPosition,
        address aavePool,
        uint256 borrowAmount
    ) public returns (uint256) {
        UserPosition(payable(userPosition)).executeBorrow(
            address(aavePool),
            address(usdc),
            borrowAmount,
            2, // Variable rate
            0 // referralCode
        );

        usdc.approve(address(this), borrowAmount);
        usdc.safeTransferFrom(userPosition, address(this), borrowAmount);

        return borrowAmount;
    }

    /// @notice Generate deposit ID
    /// @param user User address
    /// @param tokenType Token type (WBTC/USDC)
    /// @param amount Deposit amount
    /// @param timestamp Timestamp
    /// @return Deposit ID
    function generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, tokenType, amount, timestamp));
    }

    /// @notice Handle WBTC deposit
    /// @param wbtc WBTC token contract
    /// @param usdc USDC token contract
    /// @param user User address
    /// @param userPosition User position contract address
    /// @param amount Deposit amount
    /// @param referralCode Referral code
    /// @param aavePool Aave pool contract address
    /// @param aaveOracle Aave oracle contract address
    /// @param defaultLiquidationThreshold Default liquidation threshold
    /// @return borrowAmount Borrow amount
    function handleWbtcDeposit(
        IERC20 wbtc,
        IERC20 usdc,
        address user,
        address userPosition,
        uint256 amount,
        uint16 referralCode,
        address aavePool,
        address aaveOracle,
        uint256 defaultLiquidationThreshold
    ) public returns (uint256 borrowAmount) {
        // Transfer WBTC to user position and deposit into Aave
        wbtc.safeTransferFrom(user, userPosition, amount);

        UserPosition(payable(userPosition)).executeAaveDeposit(
            aavePool,
            address(wbtc),
            amount,
            referralCode
        );

        (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            ,
            ,
            uint256 currentLiquidationThreshold,

        ) = _getUserAccountData(userPosition, aavePool);

        // Calculate and borrow USDC
        borrowAmount = calculateBorrowAmount(
            IAaveOracle(aaveOracle),
            address(usdc),
            totalDebtBase,
            totalCollateralBase,
            currentLiquidationThreshold,
            defaultLiquidationThreshold
        );

        UserPosition(payable(userPosition)).executeBorrow(
            aavePool,
            address(usdc),
            borrowAmount,
            2, // Variable rate
            referralCode
        );

        return borrowAmount;
    }

    /// @notice Handle USDC deposit
    /// @param usdc USDC token contract
    /// @param user User address
    /// @param engineAddress Strategy engine contract address
    /// @param amount Deposit amount
    function handleUsdcDeposit(
        IERC20 usdc,
        address user,
        address engineAddress,
        uint256 amount
    ) public {
        usdc.safeTransferFrom(user, engineAddress, amount);
    }

    /// @notice Mark all deposits as withdrawn
    /// @param info User information struct
    function markDepositsAsWithdrawn(UserInfo storage info) public {
        for (uint256 i = 0; i < info.deposits.length; i++) {
            info.deposits[i].isWithdrawn = true;
        }
    }

    /// @notice Calculate withdrawal amounts
    /// @param info User information struct
    /// @return totalWbtcAmount Total WBTC amount
    /// @return totalUsdcAmount Total USDC amount
    /// @return totalBorrowAmount Total borrow amount
    function calculateWithdrawalAmounts(
        UserInfo storage info
    )
        public
        view
        returns (uint256 totalWbtcAmount, uint256 totalUsdcAmount, uint256 totalBorrowAmount)
    {
        for (uint256 i = 0; i < info.deposits.length; i++) {
            DepositRecord storage userDeposit = info.deposits[i];
            if (!userDeposit.isWithdrawn) {
                if (userDeposit.tokenType == TokenType.WBTC) {
                    totalWbtcAmount += userDeposit.amount;
                    totalBorrowAmount += userDeposit.borrowAmount;
                } else {
                    totalUsdcAmount += userDeposit.amount;
                }
            }
        }
    }

    /// @notice Get user account data
    /// @param user User address
    /// @param aavePool Aave pool contract address
    /// @return totalCollateralBase Total collateral base
    /// @return totalDebtBase Total debt base
    /// @return availableBorrowsBase Available borrows base
    /// @return currentLiquidationThreshold Current liquidation threshold
    /// @return ltv Loan-to-value ratio
    /// @return healthFactor Health factor
    function _getUserAccountData(
        address user,
        address aavePool
    )
        public
        view
        returns (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        )
    {
        return IAavePool(aavePool).getUserAccountData(user);
    }
}
