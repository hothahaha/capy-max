// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

import {IAavePool} from "../src/interfaces/aave/IAavePool.sol";
import {IAaveOracle} from "../src/interfaces/aave/IAaveOracle.sol";
import {IVariableDebtToken} from "../src/interfaces/aave/IVariableDebtToken.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {UserPosition} from "../src/UserPosition.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {Vault} from "../src/vault/Vault.sol";
import {ISafe} from "../src/interfaces/safe/ISafe.sol";

/**
 * @title BorrowAmountHelper
 * @notice Helper contract to test calculating borrow amount
 */
contract BorrowAmountHelper {
    StrategyEngine public engine;

    constructor(StrategyEngine _engine) {
        engine = _engine;
    }

    function calculateBorrowAmount(
        address aaveOracle,
        address usdc,
        uint256 totalCollateralBase,
        uint256 currentLiquidationThreshold,
        uint256 defaultLiquidationThreshold
    ) external view returns (uint256) {
        // Implementation of calculateBorrowAmount logic from StrategyLib
        if (totalCollateralBase == 0) {
            return 0;
        }

        // totalCollateralBase * currentLiquidationThreshold / defaultLiquidationThreshold = maxBorrowIn
        uint256 maxBorrowIn = (totalCollateralBase * currentLiquidationThreshold) /
            (defaultLiquidationThreshold * 10 ** 2);

        uint256 usdcPrice = IAaveOracle(aaveOracle).getAssetPrice(usdc);
        uint256 borrowAmount = (maxBorrowIn * 10 ** 6) / usdcPrice; // 6 is USDC decimals

        return borrowAmount;
    }
}

contract StrategyEngineTest is Test {
    // State variables
    IAavePool public aavePool;
    StrategyEngine public engine;
    address public wbtc;
    address public usdc;
    address public USER;
    address public SAFE_WALLET;
    address public DEPLOYER;
    uint256 public USER_PRIVATE_KEY;
    uint256 public DEPLOYER_PRIVATE_KEY;
    uint256 public constant INITIAL_WBTC_BALANCE = 1000e8;
    uint256 public constant GMX_EXECUTION_FEE = 0.011 ether;
    uint256 public constant HEALTH_FACTOR_THRESHOLD = 1e19; // 1.0

    CpToken public cpToken;
    Vault public vault;
    HelperConfig public helperConfig;

    address public user;

    // Additional variables from StrategyEngineAdditionalTest
    address public aaveOracle;
    address public safeWallet;
    address public user2;
    uint256 public user2PrivateKey;
    address[] public safeSigners;

    uint256 public defaultLiquidationThreshold;

    uint256 public constant INITIAL_BALANCE = 1 ether;
    uint256 public constant WBTC_AMOUNT = 1e8; // 1 WBTC
    uint256 public constant USDC_AMOUNT = 10_000e6; // 10,000 USDC

    // Events
    event PlatformFeeUpdated(uint256 oldFee, uint256 newFee);
    event Deposited(
        bytes32 indexed depositId,
        address indexed user,
        StrategyEngine.TokenType tokenType,
        uint256 amount,
        uint256 borrowAmount,
        uint256 timestamp
    );
    event Withdrawn(address indexed user, uint256 amount, uint256 rewards);
    event BorrowCapacityUpdated(
        address indexed user,
        uint256 wbtcAmount,
        uint256 originalBorrowAmount,
        uint256 newBorrowAmount,
        uint256 difference,
        bool isIncrease,
        uint256 timestamp
    );

    // Modifiers
    modifier withWBTCDeposit(uint256 amount) {
        uint256 deadline = block.timestamp + 1 days;
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            amount,
            IERC20Permit(wbtc).nonces(user),
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(user);
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            amount,
            0,
            deadline,
            v,
            r,
            s
        );
        vm.stopPrank();
        _;
    }

    modifier withUSDCDeposit(uint256 amount) {
        vm.startPrank(user);

        // Mint USDC to user
        deal(address(usdc), user, amount);

        // Approve and deposit
        IERC20(usdc).approve(address(engine), amount);
        engine.deposit(StrategyEngine.TokenType.USDC, amount, 0, 0, 0, bytes32(0), bytes32(0));
        vm.stopPrank();
        _;
    }

    function setUp() public {
        (user, USER_PRIVATE_KEY) = makeAddrAndKey("user");

        // Additional setup for users from StrategyEngineAdditionalTest
        (user2, user2PrivateKey) = makeAddrAndKey("user2");

        DeployScript deployer = new DeployScript();
        (engine, cpToken, vault, helperConfig) = deployer.run();

        // 修复类型转换问题，确保显式转换为IAavePool类型
        address _wbtc;
        address _usdc;
        address _aavePool;
        address _aaveOracle;
        uint256 _deployerKey;
        address _safeWallet;

        (_wbtc, _usdc, _aavePool, _aaveOracle, , _deployerKey, _safeWallet) = helperConfig
            .activeNetworkConfig();

        wbtc = _wbtc;
        usdc = _usdc;
        aavePool = IAavePool(_aavePool);
        aaveOracle = _aaveOracle;
        DEPLOYER_PRIVATE_KEY = _deployerKey;
        safeWallet = _safeWallet;
        SAFE_WALLET = safeWallet;
        DEPLOYER = vm.addr(DEPLOYER_PRIVATE_KEY);

        // Set up safe signers for multi-sig tests
        safeSigners = new address[](3);
        safeSigners[0] = DEPLOYER; // Make DEPLOYER a Safe signer
        for (uint i = 1; i < 3; i++) {
            (safeSigners[i], ) = makeAddrAndKey(string(abi.encodePacked("signer", i)));
        }

        // Mock Safe contract behavior for safeWallet
        vm.mockCall(
            safeWallet,
            abi.encodeWithSelector(ISafe.getOwners.selector),
            abi.encode(safeSigners)
        );

        vm.mockCall(safeWallet, abi.encodeWithSelector(ISafe.getThreshold.selector), abi.encode(2));

        // Deal ETH and tokens to users
        vm.deal(user, INITIAL_BALANCE);
        deal(wbtc, user, INITIAL_WBTC_BALANCE);
        deal(usdc, user, INITIAL_BALANCE);

        // Deal tokens to additional users
        deal(wbtc, user2, INITIAL_WBTC_BALANCE);
        deal(usdc, user2, INITIAL_BALANCE);

        defaultLiquidationThreshold = engine.getDefaultLiquidationThreshold();

        // Approve USDC for repayment
        vm.prank(user);
        IERC20(usdc).approve(address(engine), type(uint256).max);

        // Approve tokens for additional users
        vm.startPrank(user2);
        IERC20(wbtc).approve(address(engine), type(uint256).max);
        IERC20(usdc).approve(address(engine), type(uint256).max);
        vm.stopPrank();
    }

    function test_DepositWBTC() public {
        uint256 amount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        // Get current nonce for the user
        uint256 nonce = IERC20Permit(wbtc).nonces(user);

        // Generate signature for deposit
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            amount,
            nonce,
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(user);

        // Record balance before deposit
        uint256 beforeWbtcBalance = IERC20(wbtc).balanceOf(user);

        // Execute deposit
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            amount,
            0,
            deadline,
            v,
            r,
            s
        );

        // Verify state after deposit
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Verify WBTC deposit amount
        assertEq(totalWbtc, amount, "Incorrect WBTC deposit amount");
        assertEq(totalUsdc, 0, "USDC amount should be zero");

        // Verify borrow amount
        assertGt(totalBorrows, 0, "Should have borrowed USDC");

        // Verify user balance change
        assertEq(
            IERC20(wbtc).balanceOf(user),
            beforeWbtcBalance - amount,
            "Incorrect WBTC balance change"
        );

        (
            ,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            ,
            ,
            uint256 healthFactorAfterDeposit
        ) = engine.getUserAccountData(user);

        assertGt(totalDebtBase, 0, "Should have borrowed USDC");
        assertGt(availableBorrowsBase, 0, "Should have available borrows");
        assertLt(
            healthFactorAfterDeposit,
            HEALTH_FACTOR_THRESHOLD,
            "Health factor should be less than threshold after deposit and borrow"
        );
        assertGt(
            healthFactorAfterDeposit,
            defaultLiquidationThreshold,
            "Health factor should be greater than default health factor"
        );

        vm.stopPrank();
    }

    function test_WBTCDepositRecord() public {
        uint256 amount = 1e7;
        uint256 deadline = block.timestamp + 1 days;
        bytes32 expectedDepositId = engine.generateDepositId(
            user,
            StrategyEngine.TokenType.WBTC,
            amount,
            block.timestamp
        );

        uint256 nonce = IERC20Permit(wbtc).nonces(user);

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            amount,
            nonce,
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(user);
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            amount,
            0,
            deadline,
            v,
            r,
            s
        );

        // Verify deposit record
        StrategyEngine.DepositRecord[] memory records = engine.getUserDepositRecords(user);
        assertEq(records.length, 1, "Should have one deposit record");
        assertEq(records[0].depositId, expectedDepositId, "Incorrect depositId");
        assertEq(
            uint8(records[0].tokenType),
            uint8(StrategyEngine.TokenType.WBTC),
            "Incorrect token type"
        );
        assertEq(records[0].amount, amount, "Incorrect record amount");
        assertGt(records[0].borrowAmount, 0, "Should have borrow amount in record");
        assertEq(records[0].depositId, expectedDepositId);

        vm.stopPrank();
    }

    function test_DepositUSDC() public {
        uint256 amount = 1000e6; // 1000 USDC
        bytes32 expectedDepositId = engine.generateDepositId(
            user,
            StrategyEngine.TokenType.USDC,
            amount,
            block.timestamp
        );

        vm.startPrank(user);

        // Mint USDC to user
        deal(address(usdc), user, amount);

        // Record balance before deposit
        uint256 beforeUsdcBalance = IERC20(usdc).balanceOf(user);
        uint256 beforeCpTokenBalance = engine.cpToken().balanceOf(user);

        // Approve and deposit
        IERC20(usdc).approve(address(engine), amount);
        engine.deposit(StrategyEngine.TokenType.USDC, amount, 0, 0, 0, bytes32(0), bytes32(0));

        // Verify state after deposit
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Verify deposit amount
        assertEq(totalUsdc, amount, "Incorrect USDC deposit amount");
        assertEq(totalWbtc, 0, "WBTC amount should be zero");
        assertEq(totalBorrows, 0, "Should not have any borrows");

        // Verify user balance change
        assertEq(
            IERC20(usdc).balanceOf(user),
            beforeUsdcBalance - amount,
            "Incorrect USDC balance change"
        );

        // Verify cpToken was not minted
        assertEq(
            engine.cpToken().balanceOf(user),
            beforeCpTokenBalance,
            "Should not mint cpToken for USDC deposit"
        );

        // Verify deposit record
        StrategyEngine.DepositRecord[] memory records = engine.getUserDepositRecords(user);
        assertEq(records.length, 1, "Should have one deposit record");
        assertEq(
            uint8(records[0].tokenType),
            uint8(StrategyEngine.TokenType.USDC),
            "Incorrect token type"
        );
        assertEq(records[0].amount, amount, "Incorrect record amount");
        assertEq(records[0].borrowAmount, 0, "Should not have borrow amount in record");
        assertEq(records[0].depositId, expectedDepositId);

        vm.stopPrank();
    }

    function test_RevertWhen_DepositZeroAmount() public {
        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidAmount.selector);
        vm.prank(user);
        engine.deposit(StrategyEngine.TokenType.USDC, 0, 0, 0, 0, bytes32(0), bytes32(0));
    }

    function test_DepositWithExactBalance() public {
        uint256 amount = 1000e6;

        vm.startPrank(user);

        // Mint exact amount of USDC to user
        deal(address(usdc), user, amount);
        IERC20(usdc).approve(address(engine), amount);

        // Deposit exact amount
        engine.deposit(StrategyEngine.TokenType.USDC, amount, 0, 0, 0, bytes32(0), bytes32(0));

        // Verify balance is zero
        assertEq(IERC20(usdc).balanceOf(user), 0, "User balance should be zero");

        vm.stopPrank();
    }

    function test_WithdrawWBTC() public withWBTCDeposit(1e7) {
        uint256 beforeWbtcBalance = INITIAL_WBTC_BALANCE;
        // Get borrow amount
        (uint256 totalWbtc, , uint256 totalBorrows, ) = engine.getUserTotals(user);
        assertGt(totalBorrows, 0, "Should have borrowed USDC");

        // Verify WBTC balance
        assertEq(
            IERC20(wbtc).balanceOf(user),
            beforeWbtcBalance - totalWbtc,
            "Incorrect WBTC balance change"
        );

        deal(address(usdc), address(engine), totalBorrows);

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.WBTC,
            user: user,
            amount: totalBorrows
        });

        engine.withdrawBatch(withdrawals);

        // Verify state update
        (uint256 newTotalWbtc, , uint256 newTotalBorrows, ) = engine.getUserTotals(user);
        assertEq(newTotalWbtc, 0, "WBTC balance should be zero");
        assertEq(newTotalBorrows, 0, "Borrow amount should be zero");

        // Verify health factor
        (, , , , , uint256 healthFactor) = engine.getUserAccountData(user);
        assertGt(
            healthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Health factor should be greater than threshold after full repayment"
        );
    }

    function test_WithdrawUSDC() public withUSDCDeposit(1000e6) {
        // Verify deposit
        (, uint256 totalUsdc, , ) = engine.getUserTotals(user);
        assertEq(totalUsdc, 1000e6, "Incorrect USDC deposit amount");

        deal(address(usdc), address(engine), 1000e6);

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.USDC,
            user: user,
            amount: totalUsdc
        });

        engine.withdrawBatch(withdrawals);

        // Verify state update
        (, uint256 newTotalUsdc, , ) = engine.getUserTotals(user);
        assertEq(newTotalUsdc, 0, "USDC balance should be zero");
    }

    function test_WithdrawWithProfit() public withUSDCDeposit(1000e6) {
        uint256 profit = 100e6; // 100 USDC profit
        uint256 totalAmount = 1000e6 + profit;

        // Simulate profit generation
        deal(address(usdc), address(engine), totalAmount);

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.USDC,
            user: user,
            amount: totalAmount
        });

        engine.withdrawBatch(withdrawals);

        // Verify platform fee
        uint256 platformFee = (profit * engine.getPlatformFee()) / 10000; // 10% of profit
        uint256 userProfit = profit - platformFee;

        // Verify platform fee
        uint256 beforeVaultBalance = IERC20(usdc).balanceOf(address(vault));
        assertEq(beforeVaultBalance, platformFee, "Incorrect platform fee in vault");

        // Verify user reward token amount
        assertEq(engine.cpToken().balanceOf(user), userProfit, "Incorrect reward token amount");
    }

    function test_RevertWhen_WithdrawZeroAmount() public {
        // Create withdrawal info with zero amount
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.USDC,
            user: user,
            amount: 0
        });

        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidAmount.selector);
        vm.prank(user);
        engine.withdrawBatch(withdrawals);
    }

    function test_RevertWhen_WithdrawWBTCWithHighBorrow() public withWBTCDeposit(1e7) {
        // Verify health factor after deposit
        (, , , , , uint256 initialHealthFactor) = engine.getUserAccountData(user);
        assertLt(
            initialHealthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Initial health factor should be less than threshold"
        );
        assertGt(
            initialHealthFactor,
            defaultLiquidationThreshold,
            "Health factor should be greater than default health factor"
        );

        deal(address(usdc), address(engine), 1000e6);

        uint256 engineBalance = IERC20(usdc).balanceOf(address(engine));

        // Try to withdraw less than borrow amount
        uint256 invalidWithdrawAmount = engineBalance + (engineBalance * 10) / 100;

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.WBTC,
            user: user,
            amount: invalidWithdrawAmount
        });

        vm.expectRevert(StrategyEngine.StrategyEngine__InsufficientContractBalance.selector);
        engine.withdrawBatch(withdrawals);
    }

    function test_WithdrawWithUnhealthyFactor() public withWBTCDeposit(1e7) {
        // Get borrow amount
        (, , uint256 totalBorrows, ) = engine.getUserTotals(user);
        uint256 profit = totalBorrows / 2; // 50% of borrow amount as profit
        deal(address(usdc), address(engine), IERC20(usdc).balanceOf(address(engine)) + profit);

        // Withdraw less than borrow amount, so health factor is still below threshold
        uint256 withdrawAmount = totalBorrows - (totalBorrows * 50) / 100;

        // Verify health factor after deposit
        (, , , , , uint256 initialHealthFactor) = engine.getUserAccountData(user);
        assertLt(
            initialHealthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Initial health factor should be less than threshold"
        );
        assertGt(
            initialHealthFactor,
            defaultLiquidationThreshold,
            "Health factor should be greater than default health factor"
        );

        deal(address(usdc), address(engine), withdrawAmount);

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.WBTC,
            user: user,
            amount: withdrawAmount
        });

        engine.withdrawBatch(withdrawals);

        // Verify health factor after partial repayment
        (, , , , , uint256 finalHealthFactor) = engine.getUserAccountData(user);
        assertLt(
            finalHealthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Health factor should still be less than threshold after partial repayment"
        );
        assertGt(
            finalHealthFactor,
            defaultLiquidationThreshold,
            "Health factor should be greater than default health factor"
        );

        // Verify only borrow amount is updated
        (, , uint256 newTotalBorrows, ) = engine.getUserTotals(user);
        assertGt(newTotalBorrows, 0, "Borrow amount should not be zero");
    }

    function test_RepayAmountCalculation() public withWBTCDeposit(1e7) {
        // Get user position and borrow amount
        address userPosition = engine.getUserPositionAddress(user);
        (, , uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Get expected repay amount
        uint256 expectedRepayAmount = engine.calculateRepayAmount(address(usdc), userPosition);

        // Simulate USDC balance
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + totalBorrows
        );

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.WBTC,
            user: user,
            amount: totalBorrows
        });

        // Execute repayment
        (, uint256[] memory actualRepayAmounts) = engine.withdrawBatch(withdrawals);

        // Verify actual repay amount equals calculated repay amount
        assertEq(
            expectedRepayAmount,
            actualRepayAmounts[0],
            "Actual repay amount should equal calculated repay amount"
        );
    }

    function test_PartialRepayAmountCalculation() public withWBTCDeposit(1e7) {
        // Get user position and borrow amount
        address userPosition = engine.getUserPositionAddress(user);

        // Verify partial repayment
        uint256 partialAmount = 3000e6;
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + partialAmount
        );

        // Get expected partial repay amount
        uint256 expectedPartialRepayAmount = engine.calculateRepayAmount(
            address(usdc),
            userPosition
        );

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.WBTC,
            user: user,
            amount: partialAmount
        });

        // Execute partial repayment
        engine.withdrawBatch(withdrawals);

        // Verify remaining repay amount
        uint256 remainingRepayAmount = engine.calculateRepayAmount(address(usdc), userPosition);
        assertEq(
            remainingRepayAmount,
            expectedPartialRepayAmount - partialAmount,
            "Remaining repay amount incorrect after partial repayment"
        );
    }

    function test_RevertWhen_UpdatePlatformFeeUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(StrategyEngine.StrategyEngine__NotSafeSigner.selector);
        engine.updatePlatformFee(500);
    }

    function test_RevertWhen_UpdatePlatformFeeInvalidPercentage() public {
        vm.prank(DEPLOYER); // DEPLOYER is now a Safe signer
        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidFeePercentage.selector);
        engine.updatePlatformFee(10001);
    }

    function test_PlatformFeeCalculation() public {
        // Set platform fee to 10%
        vm.prank(DEPLOYER); // DEPLOYER is now a Safe signer
        engine.updatePlatformFee(1000);

        // Execute deposit and withdrawal operations, verify fee calculation
        uint256 depositAmount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            depositAmount,
            IERC20Permit(wbtc).nonces(user),
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(user);
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            depositAmount,
            0,
            deadline,
            v,
            r,
            s
        );

        (, , uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Simulate profit generation
        uint256 profit = 1000e6; // 100 USDC
        deal(usdc, address(engine), totalBorrows + profit);

        // Calculate expected platform fee
        uint256 expectedPlatformFee = (profit * engine.getPlatformFee()) / 10000; // 10%
        uint256 expectedUserProfit = profit - expectedPlatformFee;

        uint256 withdrawAmount = totalBorrows + profit;

        // Create withdrawal info
        StrategyEngine.WithdrawalInfo[] memory withdrawals = new StrategyEngine.WithdrawalInfo[](1);
        withdrawals[0] = StrategyEngine.WithdrawalInfo({
            tokenType: StrategyEngine.TokenType.WBTC,
            user: user,
            amount: withdrawAmount
        });

        uint256 beforeVaultBalance = IERC20(usdc).balanceOf(address(vault));
        (uint256[] memory actualUserProfits, ) = engine.withdrawBatch(withdrawals);

        // Verify platform fee and user profit - allow 1 wei difference due to rounding
        assertApproxEqAbs(actualUserProfits[0], expectedUserProfit, 1, "Incorrect user profit");
        assertEq(
            IERC20(usdc).balanceOf(address(vault)) - beforeVaultBalance,
            expectedPlatformFee,
            "Incorrect platform fee"
        );

        vm.stopPrank();
    }

    function test_UpdateBorrowCapacity_PriceIncrease() public withWBTCDeposit(1e7) {
        // Record initial borrow amount
        (, , uint256 initialBorrowAmount, ) = engine.getUserTotals(user);

        // Simulate price increase by manipulating oracle
        uint256 originalPrice = IAaveOracle(engine.getAaveOracleAddress()).getAssetPrice(
            address(wbtc)
        );
        vm.mockCall(
            engine.getAaveOracleAddress(),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice * 2)
        );

        // Expect event emission for increased borrowing
        vm.expectEmit(true, true, true, true);
        emit BorrowCapacityUpdated(
            user,
            1e7,
            initialBorrowAmount,
            engine.calculateBorrowAmount(engine.getUserPositionAddress(user)),
            engine.calculateBorrowAmount(engine.getUserPositionAddress(user)) - initialBorrowAmount,
            true,
            block.timestamp
        );

        // Update borrow capacity
        engine.updateBorrowCapacity(user);

        // Verify increased borrowing
        (, , uint256 newBorrowAmount, ) = engine.getUserTotals(user);
        assertGt(newBorrowAmount, initialBorrowAmount, "Borrow amount should increase");
    }

    function test_UpdateBorrowCapacity_PriceDecrease() public withWBTCDeposit(1e7) {
        // Record initial borrow amount
        (, , uint256 initialBorrowAmount, ) = engine.getUserTotals(user);

        // Simulate price decrease
        uint256 originalPrice = IAaveOracle(engine.getAaveOracleAddress()).getAssetPrice(
            address(wbtc)
        );
        vm.mockCall(
            engine.getAaveOracleAddress(),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice / 2)
        );

        // Calculate new borrow amount
        uint256 newBorrowAmount = engine.calculateBorrowAmount(engine.getUserPositionAddress(user));

        // Expect event emission for required repayment
        vm.expectEmit(true, true, true, true);
        emit BorrowCapacityUpdated(
            user,
            1e7,
            initialBorrowAmount,
            newBorrowAmount,
            initialBorrowAmount - newBorrowAmount,
            false,
            block.timestamp
        );

        // Update borrow capacity
        engine.updateBorrowCapacity(user);
    }

    function test_RepayBorrow() public withWBTCDeposit(1e7) {
        // Record initial borrow amount
        (, , uint256 initialBorrowAmount, ) = engine.getUserTotals(user);

        // Repay half of the borrowed amount
        uint256 repayAmount = initialBorrowAmount / 2;
        deal(address(usdc), address(engine), repayAmount);

        engine.repayBorrow(user, repayAmount);

        // Verify borrow amount decreased
        (, , uint256 newBorrowAmount, ) = engine.getUserTotals(user);
        assertEq(
            newBorrowAmount,
            initialBorrowAmount - repayAmount,
            "Borrow amount should decrease by repay amount"
        );
    }

    function test_RevertWhen_RepayBorrowInvalidAmount() public {
        vm.startPrank(user);
        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidAmount.selector);
        engine.repayBorrow(user, 0);
        vm.stopPrank();
    }

    function test_RevertWhen_RepayBorrowNoUserPosition() public {
        address noPositionUser = makeAddr("noPosition");
        vm.startPrank(noPositionUser);
        vm.expectRevert(StrategyEngine.StrategyEngine__NoUserPosition.selector);
        engine.repayBorrow(noPositionUser, 1e6);
        vm.stopPrank();
    }

    function test_RevertWhen_RepayBorrowAmountTooHigh() public withWBTCDeposit(1e7) {
        // Try to repay more than borrowed
        (, , uint256 borrowAmount, ) = engine.getUserTotals(user);
        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidRepayAmount.selector);
        engine.repayBorrow(user, borrowAmount + 1);
    }

    // Tests previously from StrategyEngineAdditionalTest
    /**
     * @notice Test generating deposit ID to increase coverage
     */
    function test_GenerateDepositId() public view {
        address userAddress = address(0x123);
        StrategyEngine.TokenType tokenType = StrategyEngine.TokenType.WBTC;
        uint256 amount = 1e8;
        uint256 timestamp = 1234567890;

        bytes32 depositId = engine.generateDepositId(userAddress, tokenType, amount, timestamp);

        // Verify depositId is non-zero and deterministic
        assertNotEq(depositId, bytes32(0), "Deposit ID should not be zero");

        // Generate the ID again and verify it matches
        bytes32 depositId2 = engine.generateDepositId(userAddress, tokenType, amount, timestamp);
        assertEq(depositId, depositId2, "Generated IDs should be deterministic");
    }

    /**
     * @notice Test withdrawByUser function to increase coverage
     */
    function test_WithdrawByUser() public {
        // First, deposit WBTC
        uint256 depositAmount = WBTC_AMOUNT;
        _depositWbtc(user2, depositAmount, user2PrivateKey);

        // Verify deposit was recorded
        (uint256 totalWbtc, , uint256 totalBorrows, ) = engine.getUserTotals(user2);
        assertEq(totalWbtc, depositAmount, "WBTC deposit should be recorded");
        assertGt(totalBorrows, 0, "Should have borrowed funds");

        // Ensure there's enough USDC for repayment
        deal(usdc, address(engine), 10 * totalBorrows);

        // Repay borrowed amount
        vm.prank(safeWallet);
        engine.repayBorrow(user2, totalBorrows);

        // Now withdraw the funds for the user
        uint256 user2WbtcBalanceBefore = IERC20(wbtc).balanceOf(user2);

        vm.prank(address(engine));
        engine.withdrawByUser(user2);

        // Verify user2 received their deposited WBTC back
        uint256 user2WbtcBalanceAfter = IERC20(wbtc).balanceOf(user2);
        assertGt(
            user2WbtcBalanceAfter,
            user2WbtcBalanceBefore,
            "User should have received WBTC back"
        );
    }

    /**
     * @notice Test getUserAccountData functions to increase coverage
     */
    function test_GetUserAccountData_Additional() public {
        // Create a user position
        _depositWbtc(user2, WBTC_AMOUNT, user2PrivateKey);

        // Call getUserAccountData for a user
        (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            ,
            uint256 currentLiquidationThreshold,
            ,

        ) = engine.getUserAccountData(user2);

        // Verify we got meaningful data
        assertGt(totalCollateralBase, 0, "Should have collateral base");
        assertGt(totalDebtBase, 0, "Should have debt base");
        assertGt(currentLiquidationThreshold, 0, "Should have liquidation threshold");
    }

    /**
     * @notice Test calculateRepayAmount function to increase coverage
     */
    function test_CalculateRepayAmount_Additional() public {
        // Create a user position
        _depositWbtc(user2, WBTC_AMOUNT, user2PrivateKey);

        // Get user position address
        address userPosition = engine.getUserPositionAddress(user2);

        // Calculate repay amount
        uint256 repayAmount = engine.calculateRepayAmount(address(usdc), userPosition);

        // Verify we got a meaningful amount
        assertGt(repayAmount, 0, "Repay amount should be greater than zero");
    }

    /**
     * @notice Test getUserDepositRecords and getUserTotals functions to increase coverage
     */
    function test_GetUserData() public {
        // Create user deposits
        _depositWbtc(user2, WBTC_AMOUNT, user2PrivateKey);
        _depositUsdc(user2, USDC_AMOUNT);

        // Get deposit records
        StrategyEngine.DepositRecord[] memory records = engine.getUserDepositRecords(user2);

        // Verify we got the records
        assertEq(records.length, 2, "Should have 2 deposit records");

        // Get user totals
        (
            uint256 totalWbtc,
            uint256 totalUsdc,
            uint256 totalBorrows,
            uint256 lastDepositTime
        ) = engine.getUserTotals(user2);

        // Verify totals
        assertEq(totalWbtc, WBTC_AMOUNT, "WBTC total should match deposit");
        assertEq(totalUsdc, USDC_AMOUNT, "USDC total should match deposit");
        assertGt(totalBorrows, 0, "Should have some borrows");
        assertEq(lastDepositTime, block.timestamp, "Last deposit time should be now");
    }

    /**
     * @notice Test getPlatformFee, getDefaultLiquidationThreshold, getUSDCBalance functions to increase coverage
     */
    function test_GetterFunctions() public view {
        // Test platform fee getter
        uint256 platformFee = engine.getPlatformFee();
        assertEq(platformFee, 1000, "Platform fee should be 10%");

        // Test liquidation threshold getter
        uint256 threshold = engine.getDefaultLiquidationThreshold();
        assertEq(threshold, 156, "Default liquidation threshold should be 156");

        // Test USDC balance getter
        uint256 usdcBalance = engine.getUSDCBalance();
        assertEq(
            usdcBalance,
            IERC20(usdc).balanceOf(address(engine)),
            "USDC balance should match actual balance"
        );

        // Test token address getters
        assertEq(engine.getWBTCAddress(), wbtc, "WBTC address should match");
        assertEq(engine.getUSDCAddress(), usdc, "USDC address should match");
        assertEq(
            address(engine.getAavePoolAddress()),
            address(aavePool),
            "Aave pool address should match"
        );
        assertEq(engine.getAaveOracleAddress(), aaveOracle, "Aave oracle address should match");
        assertEq(engine.getVaultAddress(), address(vault), "Vault address should match");
    }

    /**
     * @notice Test calculateBorrowAmount function to increase coverage
     */
    function test_CalculateBorrowAmount_Helper() public {
        // Create a user position with a deposit
        _depositWbtc(user2, WBTC_AMOUNT, user2PrivateKey);

        // Create helper contract
        BorrowAmountHelper helper = new BorrowAmountHelper(engine);

        // Get references to key contracts and addresses
        address aaveOracleAddr = engine.getAaveOracleAddress();
        address usdcAddress = engine.getUSDCAddress();

        // Mock the Aave oracle price responses for both tokens
        vm.mockCall(
            aaveOracleAddr,
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, usdcAddress),
            abi.encode(10 ** 8) // $1.00 with 8 decimals precision
        );

        // Calculate borrow amount using our helper
        uint256 borrowAmount = helper.calculateBorrowAmount(
            aaveOracleAddr,
            usdcAddress,
            10_000 * 10 ** 8, // totalCollateralBase
            8000, // currentLiquidationThreshold (80%)
            156 // defaultLiquidationThreshold (1.56 or 156%)
        );

        // Now the borrowAmount should be non-zero
        assertGt(borrowAmount, 0, "Borrow amount should be greater than zero");
        console2.log("Calculated borrow amount: ", borrowAmount);
    }

    // Helper functions at the end
    function _depositWbtc(address userAddress, uint256 amount, uint256 privateKey) internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = 0;

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            userAddress,
            address(engine),
            amount,
            nonce,
            deadline,
            privateKey
        );

        vm.prank(userAddress);
        engine.deposit{value: 0}(
            StrategyEngine.TokenType.WBTC,
            amount,
            0, // referralCode
            deadline,
            v,
            r,
            s
        );
    }

    function _depositUsdc(address userAddr, uint256 amount) internal {
        vm.prank(userAddr);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            amount,
            0, // referralCode
            0, // deadline (not needed)
            0, // v (not needed)
            bytes32(0), // r (not needed)
            bytes32(0) // s (not needed)
        );
    }

    function _getPermitSignature(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        // Mock the permit signature
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        bytes32 DOMAIN_SEPARATOR = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("Wrapped BTC"),
                keccak256("1"),
                block.chainid,
                token
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, amount, nonce, deadline)
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        (v, r, s) = vm.sign(privateKey, digest);
    }
}
