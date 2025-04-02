// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

import {IAavePool} from "../src/interfaces/aave/IAavePool.sol";
import {IAaveOracle} from "../src/interfaces/aave/IAaveOracle.sol";
import {IVariableDebtToken} from "../src/interfaces/aave/IVariableDebtToken.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {IStrategyEngine} from "../src/interfaces/IStrategyEngine.sol";
import {UserPosition} from "../src/UserPosition.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {Vault} from "../src/vault/Vault.sol";
import {ISafe} from "../src/interfaces/safe/ISafe.sol";
import {StrategyLib} from "../src/libraries/StrategyLib.sol";

error StrategyEngine__InvalidAmount();
error StrategyEngine__NoUserPosition();

contract StrategyEngineTest is Test {
    using SafeERC20 for IERC20;

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

    function setUp() public {
        (user, USER_PRIVATE_KEY) = makeAddrAndKey("user");

        // Additional setup for users from StrategyEngineAdditionalTest
        (user2, user2PrivateKey) = makeAddrAndKey("user2");

        DeployScript deployer = new DeployScript();
        (engine, cpToken, vault, helperConfig) = deployer.run();

        // Fix type conversion issue, ensure explicit conversion to IAavePool type
        address _aavePool;

        (wbtc, usdc, _aavePool, aaveOracle, , DEPLOYER_PRIVATE_KEY, SAFE_WALLET) = helperConfig
            .activeNetworkConfig();

        aavePool = IAavePool(_aavePool);
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

        defaultLiquidationThreshold = engine.getDefaultLiquidationThreshold() * 10 ** 16;

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
        // Record balance before deposit
        uint256 beforeWbtcBalance = IERC20(wbtc).balanceOf(user);

        uint256 amount = 1e7;
        _depositWbtcWithPermit(user, amount, USER_PRIVATE_KEY);

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
        _depositWbtcWithPermit(user, amount, USER_PRIVATE_KEY);
        bytes32 expectedDepositId = StrategyLib.generateDepositId(
            user,
            StrategyLib.TokenType.WBTC,
            amount,
            block.timestamp
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
        bytes32 expectedDepositId = StrategyLib.generateDepositId(
            user,
            StrategyLib.TokenType.USDC,
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

    function test_WithdrawWBTC() public {
        _depositWbtcWithPermit(user, 1e7, USER_PRIVATE_KEY);

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

        // Prepare withdrawal parameters
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user;
        amounts[0] = totalBorrows;

        vm.prank(DEPLOYER);
        engine.withdrawBatch(users, amounts);

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

    function test_WithdrawUSDC() public {
        uint256 amount = 1000e6;
        _depositUsdc(user, amount);

        // Verify deposit
        (, uint256 totalUsdc, , ) = engine.getUserTotals(user);
        assertEq(totalUsdc, amount, "Incorrect USDC deposit amount");

        deal(address(usdc), address(engine), 1000e6);

        // Prepare withdrawal parameters
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user;
        amounts[0] = totalUsdc;

        vm.prank(DEPLOYER);
        engine.withdrawBatch(users, amounts);

        // Verify state update
        (, uint256 newTotalUsdc, , ) = engine.getUserTotals(user);
        assertEq(newTotalUsdc, 0, "USDC balance should be zero");
    }

    function test_WithdrawWithProfit() public {
        uint256 amount = 1000e6;
        _depositUsdc(user, amount);

        uint256 profit = 100e6; // 100 USDC profit
        uint256 totalAmount = amount + profit;

        // Simulate profit generation
        deal(address(usdc), address(engine), totalAmount);

        // Prepare withdrawal parameters
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user;
        amounts[0] = totalAmount;

        vm.prank(DEPLOYER);
        engine.withdrawBatch(users, amounts);

        // Verify platform fee
        uint256 platformFee = (profit * engine.getPlatformFee()) / 10000; // 10% of profit
        uint256 beforeVaultBalance = IERC20(usdc).balanceOf(address(vault));
        assertEq(beforeVaultBalance, platformFee, "Incorrect platform fee in vault");
    }

    function test_RevertWhen_WithdrawZeroAmount() public {
        // Prepare withdrawal parameters with zero amount
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user;
        amounts[0] = 0;

        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidAmount.selector);
        vm.prank(DEPLOYER);
        engine.withdrawBatch(users, amounts);
    }

    function test_RevertWhen_WithdrawWBTCWithHighBorrow() public {
        _depositWbtcWithPermit(user, 1e7, USER_PRIVATE_KEY);
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

        // Prepare withdrawal parameters with amount exceeding contract balance
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user;
        amounts[0] = invalidWithdrawAmount;

        vm.expectRevert(StrategyEngine.StrategyEngine__InsufficientContractBalance.selector);
        vm.prank(DEPLOYER);
        engine.withdrawBatch(users, amounts);
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

        vm.prank(user);
        engine.deposit(StrategyEngine.TokenType.WBTC, depositAmount, 0, deadline, v, r, s);

        (, , uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Simulate profit generation
        uint256 profit = 1000e6; // 100 USDC
        deal(usdc, address(engine), totalBorrows + profit);

        // Calculate expected platform fee
        uint256 expectedPlatformFee = (profit * engine.getPlatformFee()) / 10000; // 10%
        uint256 expectedUserProfit = profit - expectedPlatformFee;

        uint256 withdrawAmount = totalBorrows + profit;

        // Prepare withdrawal parameters
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user;
        amounts[0] = withdrawAmount;

        uint256 beforeVaultBalance = IERC20(usdc).balanceOf(address(vault));
        vm.prank(DEPLOYER);
        uint256[] memory actualUserProfits = engine.withdrawBatch(users, amounts);

        // Verify platform fee and user profit - allow 1 wei difference due to rounding
        assertApproxEqAbs(actualUserProfits[0], expectedUserProfit, 1, "Incorrect user profit");
        assertEq(
            IERC20(usdc).balanceOf(address(vault)) - beforeVaultBalance,
            expectedPlatformFee,
            "Incorrect platform fee"
        );
    }

    /* function test_UpdateBorrowCapacity_PriceIncrease() public {
        // Initial WBTC deposit
        _depositWbtcWithPermit(user, 1e7, USER_PRIVATE_KEY);

        // Record initial state
        (uint256 totalCollateralBase, , , , , ) = engine.getUserAccountData(user);
        (, , uint256 initialBorrowAmount, ) = engine.getUserTotals(user);

        // Simulate price increase by doubling WBTC price
        uint256 originalPrice = IAaveOracle(engine.getAaveOracleAddress()).getAssetPrice(
            address(wbtc)
        );

        // Mock the price increase
        vm.mockCall(
            engine.getAaveOracleAddress(),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice * 2)
        );

        // Calculate expected new borrow amount based on doubled collateral value
        uint256 expectedNewBorrowAmount = engine.calculateBorrowAmount(
            engine.getUserPositionAddress(user)
        );
        uint256 borrowIncrease = expectedNewBorrowAmount - initialBorrowAmount;

        // Expect event emission for increased borrowing
        vm.expectEmit(true, true, true, true);
        emit BorrowCapacityUpdated(
            user,
            1e7, // WBTC amount
            initialBorrowAmount,
            expectedNewBorrowAmount,
            borrowIncrease,
            true,
            block.timestamp
        );

        // Update borrow capacity
        engine.updateBorrowCapacity(user);

        // Verify increased borrowing
        (, , uint256 newBorrowAmount, ) = engine.getUserTotals(user);
        assertGt(newBorrowAmount, initialBorrowAmount, "Borrow amount should increase");
        assertEq(
            newBorrowAmount,
            expectedNewBorrowAmount,
            "New borrow amount should match expected"
        );

        // Verify collateral value increased
        (uint256 newTotalCollateralBase, , , , , ) = engine.getUserAccountData(user);
        assertEq(newTotalCollateralBase, totalCollateralBase * 2, "Collateral value should double");
    }

    function test_UpdateBorrowCapacity_PriceDecrease() public {
        _depositWbtcWithPermit(user, 1e7, USER_PRIVATE_KEY);

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
    } */

    function test_RepayBorrow() public {
        // Setup
        uint256 depositAmount = 1e7;
        _depositWbtcWithPermit(user, depositAmount, USER_PRIVATE_KEY);

        // Get total borrows and calculate repay amount
        (, , uint256 totalBorrows, ) = engine.getUserTotals(user);
        uint256 repayAmount = totalBorrows / 2;
        require(repayAmount > 0, "Repay amount must be greater than 0");

        // Transfer USDC to engine for repayment
        deal(usdc, address(engine), repayAmount);

        // Create repay info array
        StrategyEngine.RepayInfo[] memory repayInfos = new StrategyEngine.RepayInfo[](1);
        repayInfos[0] = StrategyEngine.RepayInfo({user: user, amount: repayAmount});

        // Execute repay
        vm.prank(DEPLOYER);
        engine.repayBorrowBatch(repayInfos);

        // Verify
        (, , uint256 newBorrows, ) = engine.getUserTotals(user);
        assertEq(newBorrows, totalBorrows - repayAmount);
    }

    function test_RepayBorrow_ZeroAmount() public {
        vm.startPrank(DEPLOYER);
        // Create repay info array
        StrategyEngine.RepayInfo[] memory repayInfos = new StrategyEngine.RepayInfo[](1);
        repayInfos[0] = StrategyEngine.RepayInfo({user: user, amount: 0});

        vm.expectRevert(StrategyEngine__InvalidAmount.selector);
        engine.repayBorrowBatch(repayInfos);
        vm.stopPrank();
    }

    function test_RepayBorrow_NoPosition() public {
        vm.startPrank(DEPLOYER);
        address noPositionUser = makeAddr("noPositionUser");
        // Create repay info array
        StrategyEngine.RepayInfo[] memory repayInfos = new StrategyEngine.RepayInfo[](1);
        repayInfos[0] = StrategyEngine.RepayInfo({user: noPositionUser, amount: 1e6});

        vm.expectRevert(StrategyEngine__NoUserPosition.selector);
        engine.repayBorrowBatch(repayInfos);
        vm.stopPrank();
    }

    function test_RepayBorrow_InvalidAmount() public {
        uint256 depositAmount = 1e7;
        _depositWbtcWithPermit(user, depositAmount, USER_PRIVATE_KEY);

        // Create repay info array
        StrategyEngine.RepayInfo[] memory repayInfos = new StrategyEngine.RepayInfo[](1);
        repayInfos[0] = StrategyEngine.RepayInfo({user: user, amount: 0});

        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidAmount.selector);
        vm.startPrank(DEPLOYER);
        engine.repayBorrowBatch(repayInfos);
        vm.stopPrank();
    }

    function test_RepayBorrowMultipleUsers() public {
        // Setup user1
        uint256 depositAmount1 = 1e7;
        vm.prank(user);
        _depositWbtcWithPermit(user, depositAmount1, USER_PRIVATE_KEY);

        // Setup user2
        uint256 depositAmount2 = 2e7;
        vm.prank(user2);
        _depositWbtcWithPermit(user2, depositAmount2, user2PrivateKey);

        // Get total borrows for both users
        (, , uint256 totalBorrows1, ) = engine.getUserTotals(user);
        (, , uint256 totalBorrows2, ) = engine.getUserTotals(user2);

        // Create repay info array
        StrategyEngine.RepayInfo[] memory repayInfos = new StrategyEngine.RepayInfo[](2);
        repayInfos[0] = StrategyEngine.RepayInfo({user: user, amount: totalBorrows1});
        repayInfos[1] = StrategyEngine.RepayInfo({user: user2, amount: totalBorrows2});

        // Execute repay
        vm.prank(DEPLOYER);
        engine.repayBorrowBatch(repayInfos);

        // Verify
        (, , uint256 newBorrows1, ) = engine.getUserTotals(user);
        (, , uint256 newBorrows2, ) = engine.getUserTotals(user2);
        assertEq(newBorrows1, 0);
        assertEq(newBorrows2, 0);
        vm.stopPrank();
    }

    /**
     * @notice Test withdrawByUser function to increase coverage
     */
    function test_WithdrawByUser() public {
        // First, deposit WBTC
        uint256 depositAmount = WBTC_AMOUNT;
        _depositWbtcWithPermit(user2, depositAmount, user2PrivateKey);

        // Verify deposit was recorded
        (uint256 totalWbtc, , uint256 totalBorrows, ) = engine.getUserTotals(user2);
        assertEq(totalWbtc, depositAmount, "WBTC deposit should be recorded");
        assertGt(totalBorrows, 0, "Should have borrowed funds");

        // Ensure there's enough USDC for repayment
        deal(usdc, address(engine), 10 * totalBorrows);

        // Repay borrowed amount
        vm.startPrank(DEPLOYER);
        StrategyEngine.RepayInfo[] memory repayInfos = new StrategyEngine.RepayInfo[](1);
        repayInfos[0] = StrategyEngine.RepayInfo({user: user2, amount: totalBorrows});
        engine.repayBorrowBatch(repayInfos);
        vm.stopPrank();

        // Now withdraw the funds for the user
        vm.startPrank(user2);
        engine.withdrawByUser();
        vm.stopPrank();

        // Verify user2 received their deposited WBTC back
        uint256 user2WbtcBalanceAfter = IERC20(wbtc).balanceOf(user2);
        assertEq(
            user2WbtcBalanceAfter,
            INITIAL_WBTC_BALANCE,
            "User should have received WBTC back"
        );
    }

    /**
     * @notice Test getUserAccountData functions to increase coverage
     */
    function test_GetUserAccountData_Additional() public {
        // Create a user position
        _depositWbtcWithPermit(user2, WBTC_AMOUNT, user2PrivateKey);

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
        _depositWbtcWithPermit(user2, WBTC_AMOUNT, user2PrivateKey);

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
        _depositWbtcWithPermit(user2, WBTC_AMOUNT, user2PrivateKey);
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

    struct DepositTestInfo {
        uint256 wbtcAmount1;
        uint256 wbtcAmount2;
        uint256 usdcAmount;
        uint256 borrowAmount1;
        uint256 borrowAmount2;
        uint256 totalBorrows;
        uint256 beforeUsdcBalance;
        uint256 beforeWbtcBalance;
        uint256 profit;
    }

    function _executeMultipleDeposits(
        address _user,
        uint256 wbtcAmount1,
        uint256 wbtcAmount2,
        uint256 usdcAmount,
        uint256 privateKey
    ) internal returns (DepositTestInfo memory info) {
        info.wbtcAmount1 = wbtcAmount1;
        info.wbtcAmount2 = wbtcAmount2;
        info.usdcAmount = usdcAmount;

        // First WBTC deposit
        info.borrowAmount1 = _depositWbtcWithPermit(_user, wbtcAmount1, privateKey);

        // USDC deposit
        info.beforeUsdcBalance = _depositUsdc(_user, usdcAmount);

        // Second WBTC deposit
        info.borrowAmount2 = _depositWbtcWithPermit(_user, wbtcAmount2, privateKey);

        info.totalBorrows = info.borrowAmount2;
        info.beforeWbtcBalance = IERC20(wbtc).balanceOf(_user);

        return info;
    }

    function _executeWithdrawal(
        address _user,
        uint256 totalAmount
    ) internal returns (uint256[] memory profits) {
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = _user;
        amounts[0] = totalAmount;

        vm.prank(DEPLOYER);
        return engine.withdrawBatch(users, amounts);
    }

    function test_WithdrawBatchMultipleDeposits() public {
        // Setup deposits
        DepositTestInfo memory info = _executeMultipleDeposits(
            user,
            5e6, // wbtcAmount1
            3e6, // wbtcAmount2
            1000e6, // usdcAmount
            USER_PRIVATE_KEY
        );

        // Get health factor after multiple deposits
        (, , , , , uint256 healthFactor) = engine.getUserAccountData(user);

        // Verify health factor is greater than liquidation threshold but less than 1.0
        assertGt(
            healthFactor,
            defaultLiquidationThreshold,
            "Health factor should be greater than liquidation threshold"
        );
        assertLt(healthFactor, HEALTH_FACTOR_THRESHOLD, "Health factor should be less than 1.0");

        // Verify initial state
        _verifyWithdrawalState(
            user,
            info.wbtcAmount1 + info.wbtcAmount2,
            info.usdcAmount,
            info.totalBorrows
        );

        // Prepare for withdrawal
        uint256 buffer = 100000e6;
        uint256 totalWithdrawAmount = info.totalBorrows + info.usdcAmount + buffer;
        _prepareContractBalance(totalWithdrawAmount);

        // Execute withdrawal
        uint256[] memory profits = _executeWithdrawal(user, totalWithdrawAmount);
        info.profit = profits[0];

        // Verify results
        _verifyWithdrawalResults(info);

        // Verify final state
        _verifyWithdrawalState(user, 0, 0, 0);
    }

    function _verifyWithdrawalResults(DepositTestInfo memory info) internal view {
        // Verify token balances
        _verifyTokenBalances(
            user,
            info.beforeWbtcBalance,
            info.beforeUsdcBalance,
            info.wbtcAmount1 + info.wbtcAmount2,
            info.profit
        );
    }

    // Helper functions at the end
    function _depositWbtcWithPermit(
        address _user,
        uint256 amount,
        uint256 privateKey
    ) internal returns (uint256 borrowAmount) {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IERC20Permit(wbtc).nonces(_user);

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            _user,
            address(engine),
            amount,
            nonce,
            deadline,
            privateKey
        );

        vm.startPrank(_user);
        engine.deposit(StrategyEngine.TokenType.WBTC, amount, 0, deadline, v, r, s);
        vm.stopPrank();

        (, , borrowAmount, ) = engine.getUserTotals(_user);
        return borrowAmount;
    }

    function _depositUsdc(address _user, uint256 amount) internal returns (uint256 beforeBalance) {
        vm.startPrank(_user);
        deal(address(usdc), _user, amount);
        beforeBalance = IERC20(usdc).balanceOf(_user);
        IERC20(usdc).approve(address(engine), amount);
        engine.deposit(StrategyEngine.TokenType.USDC, amount, 0, 0, 0, bytes32(0), bytes32(0));
        vm.stopPrank();

        return beforeBalance;
    }

    function _verifyWithdrawalState(
        address _user,
        uint256 expectedWbtc,
        uint256 expectedUsdc,
        uint256 expectedBorrows
    ) internal view {
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(
            _user
        );

        assertEq(totalWbtc, expectedWbtc, "Incorrect WBTC balance");
        assertEq(totalUsdc, expectedUsdc, "Incorrect USDC balance");
        assertEq(totalBorrows, expectedBorrows, "Incorrect borrow amount");
    }

    function _verifyTokenBalances(
        address _user,
        uint256 beforeWbtcBalance,
        uint256 beforeUsdcBalance,
        uint256 expectedWbtcChange,
        uint256 profit
    ) internal view {
        uint256 afterWbtcBalance = IERC20(wbtc).balanceOf(_user);
        uint256 afterUsdcBalance = IERC20(usdc).balanceOf(_user);

        assertEq(
            afterWbtcBalance - beforeWbtcBalance,
            expectedWbtcChange,
            "Incorrect WBTC balance change"
        );
        assertEq(afterUsdcBalance - profit, beforeUsdcBalance, "Incorrect USDC balance change");
    }

    function _prepareContractBalance(uint256 amount) internal {
        deal(address(usdc), address(engine), amount);
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
