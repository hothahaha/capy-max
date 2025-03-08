// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

import {IAavePool} from "../src/aave/interface/IAavePool.sol";
import {IAaveOracle} from "../src/aave/interface/IAaveOracle.sol";
import {IVariableDebtToken} from "../src/aave/interface/IVariableDebtToken.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {UserPosition} from "../src/UserPosition.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {Vault} from "../src/vault/Vault.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {MultiSig} from "../src/access/MultiSig.sol";

contract StrategyEngineTest is Test {
    IAavePool public aavePool;
    StrategyEngine public engine;
    address public wbtc;
    address public usdc;
    address public USER;
    address public DEPLOYER;
    uint256 public USER_PRIVATE_KEY;
    uint256 public DEPLOYER_PRIVATE_KEY;
    uint256 public constant INITIAL_ETH_BALANCE = 10 ether;
    uint256 public constant INITIAL_WBTC_BALANCE = 1000e8;
    uint256 public constant GMX_EXECUTION_FEE = 0.011 ether;
    uint256 public constant HEALTH_FACTOR_THRESHOLD = 1e19; // 1.0

    // GMX related addresses
    address public constant GMX_ROUTER = 0x7C68C7866A64FA2160F78EEaE12217FFbf871fa8;
    address public constant GMX_ROUTER_PLUGIN = 0x7452c558d45f8afC8c83dAe62C3f8A5BE19c71f6;
    bytes32 public constant ROUTER_PLUGIN_ROLE = keccak256("ROUTER_PLUGIN");

    CpToken public cpToken;
    Vault public vault;
    SignerManager public signerManager;
    MultiSig public multiSig;
    HelperConfig public helperConfig;

    address public user;
    address public signer1;
    address public signer2;
    uint256 public signer1Key;
    uint256 public signer2Key;

    uint256 public defaultLiquidationThreshold;

    uint256 public constant INITIAL_BALANCE = 1 ether;

    event PlatformFeeUpdated(uint256 oldFee, uint256 newFee);
    event Deposited(
        bytes32 indexed depositId,
        address indexed user,
        StrategyEngine.TokenType tokenType,
        uint256 amount,
        uint256 borrowAmount
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
        (signer1, signer1Key) = makeAddrAndKey("signer1");
        (signer2, signer2Key) = makeAddrAndKey("signer2");

        DeployScript deployer = new DeployScript();
        (engine, cpToken, vault, signerManager, multiSig, helperConfig) = deployer.run();

        (wbtc, usdc, , , , DEPLOYER_PRIVATE_KEY, , ) = helperConfig.activeNetworkConfig();

        DEPLOYER = vm.addr(DEPLOYER_PRIVATE_KEY);

        // Deal ETH and tokens to user
        vm.deal(user, INITIAL_BALANCE);
        deal(wbtc, user, INITIAL_WBTC_BALANCE);
        deal(usdc, user, INITIAL_BALANCE);

        defaultLiquidationThreshold = engine.getDefaultLiquidationThreshold();

        // Approve USDC for repayment
        vm.prank(user);
        IERC20(usdc).approve(address(engine), type(uint256).max);
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

    // Deposit modifier
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

    // Add USDC deposit modifier
    modifier withUSDCDeposit(uint256 amount) {
        vm.startPrank(user);

        // Mint USDC to user
        deal(address(usdc), user, amount);

        // Approve and deposit
        IERC20(usdc).approve(address(engine), amount);
        engine.deposit(StrategyEngine.TokenType.USDC, amount, 0, 0, 0, bytes32(0), bytes32(0));
        _;
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

        // Withdraw
        engine.withdraw(StrategyEngine.TokenType.WBTC, user, totalBorrows);

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

        engine.withdraw(StrategyEngine.TokenType.USDC, user, totalUsdc);

        // Verify state update
        (, uint256 newTotalUsdc, , ) = engine.getUserTotals(user);
        assertEq(newTotalUsdc, 0, "USDC balance should be zero");
    }

    function test_WithdrawWithProfit() public withUSDCDeposit(1000e6) {
        uint256 profit = 100e6; // 100 USDC profit
        uint256 totalAmount = 1000e6 + profit;

        // Simulate profit generation
        deal(address(usdc), address(engine), totalAmount);

        // Withdraw all amount (including profit)
        engine.withdraw(StrategyEngine.TokenType.USDC, user, totalAmount);

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
        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidAmount.selector);
        vm.prank(user);
        engine.withdraw(StrategyEngine.TokenType.USDC, user, 0);
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

        vm.expectRevert(StrategyEngine.StrategyEngine__WithdrawAmountTooHigh.selector);
        // Try to withdraw less than borrow amount
        uint256 invalidWithdrawAmount = engineBalance + (engineBalance * 10) / 100;
        engine.withdraw(StrategyEngine.TokenType.WBTC, user, invalidWithdrawAmount);
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

        // Try to withdraw
        engine.withdraw(StrategyEngine.TokenType.WBTC, user, withdrawAmount);

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
        address userPosition = engine.userToPosition(user);
        (, , uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Get expected repay amount
        uint256 expectedRepayAmount = engine.calculateRepayAmount(address(usdc), userPosition);

        // Simulate USDC balance
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + totalBorrows
        );

        // Execute repayment
        (, uint256 actualRepayAmount) = engine.withdraw(
            StrategyEngine.TokenType.WBTC,
            user,
            totalBorrows
        );

        // Verify actual repay amount equals calculated repay amount
        assertEq(
            expectedRepayAmount,
            actualRepayAmount,
            "Actual repay amount should equal calculated repay amount"
        );
    }

    function test_PartialRepayAmountCalculation() public withWBTCDeposit(1e7) {
        // Get user position and borrow amount
        address userPosition = engine.userToPosition(user);

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

        // Execute partial repayment
        engine.withdraw(StrategyEngine.TokenType.WBTC, user, partialAmount);

        // Verify remaining repay amount
        uint256 remainingRepayAmount = engine.calculateRepayAmount(address(usdc), userPosition);
        assertEq(
            remainingRepayAmount,
            expectedPartialRepayAmount - partialAmount,
            "Remaining repay amount incorrect after partial repayment"
        );
    }

    function test_UpdatePlatformFeeUseNewSigner() public {
        uint256 newFee = 500; // 5%
        uint256 deadline = block.timestamp + 1 days;

        // Verify DEPLOYER is signer
        assertTrue(signerManager.isSigner(DEPLOYER), "DEPLOYER should be initial signer");

        // Use DEPLOYER as initial signer to add signer1
        bytes memory addSigner1Data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer1
        );
        bytes32 addSigner1TxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addSigner1Data,
            multiSig.nonce(),
            deadline
        );
        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(DEPLOYER_PRIVATE_KEY, addSigner1TxHash);
        vm.prank(DEPLOYER);
        multiSig.executeTransaction(address(signerManager), addSigner1Data, deadline, signatures);

        // Add signer2 through multiSig
        bytes memory addSigner2Data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer2
        );
        bytes32 addSigner2TxHash = _hashTransaction(
            address(multiSig),
            address(signerManager),
            addSigner2Data,
            multiSig.nonce(),
            deadline
        );
        signatures[0] = _signTransaction(DEPLOYER_PRIVATE_KEY, addSigner2TxHash);
        vm.prank(DEPLOYER);
        multiSig.executeTransaction(address(signerManager), addSigner2Data, deadline, signatures);

        // Execute multiSig transaction
        vm.prank(signer1);
        engine.updatePlatformFee(newFee);

        assertEq(engine.getPlatformFee(), newFee, "Platform fee not updated correctly");
    }

    function test_RevertWhen_UpdatePlatformFeeUnauthorized() public {
        vm.prank(user);
        vm.expectRevert(StrategyEngine.StrategyEngine__Unauthorized.selector);
        engine.updatePlatformFee(500);
    }

    function test_RevertWhen_UpdatePlatformFeeInvalidPercentage() public {
        vm.prank(DEPLOYER);
        vm.expectRevert(StrategyEngine.StrategyEngine__InvalidFeePercentage.selector);
        engine.updatePlatformFee(10001);
    }

    function test_PlatformFeeCalculation() public {
        // Set platform fee to 10%
        vm.prank(DEPLOYER);
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

        // Execute withdrawal
        uint256 beforeVaultBalance = IERC20(usdc).balanceOf(address(vault));
        (uint256 actualUserProfit, ) = engine.withdraw(
            StrategyEngine.TokenType.WBTC,
            user,
            withdrawAmount
        );

        // Verify platform fee and user profit - allow 1 wei difference due to rounding
        assertApproxEqAbs(actualUserProfit, expectedUserProfit, 1, "Incorrect user profit");
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
        uint256 originalPrice = engine.aaveOracle().getAssetPrice(address(wbtc));
        vm.mockCall(
            address(engine.aaveOracle()),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice * 2)
        );

        // Expect event emission for increased borrowing
        vm.expectEmit(true, true, true, true);
        emit BorrowCapacityUpdated(
            user,
            1e7,
            initialBorrowAmount,
            engine.calculateBorrowAmount(engine.userToPosition(user)),
            engine.calculateBorrowAmount(engine.userToPosition(user)) - initialBorrowAmount,
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
        uint256 originalPrice = engine.aaveOracle().getAssetPrice(address(wbtc));
        vm.mockCall(
            address(engine.aaveOracle()),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice / 2)
        );

        // Calculate new borrow amount
        uint256 newBorrowAmount = engine.calculateBorrowAmount(engine.userToPosition(user));

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

    // Helper functions
    function _getPermitSignature(
        address token,
        address owner,
        address spender,
        uint256 amount,
        uint256 nonce,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        bytes32 DOMAIN_SEPARATOR = IERC20Permit(token).DOMAIN_SEPARATOR();

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, amount, nonce, deadline)
        );

        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));

        (v, r, s) = vm.sign(privateKey, digest);
    }

    function _hashTransaction(
        address verifyingContract,
        address to,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 txHash = MultiSig(verifyingContract).hashTransaction(to, data, nonce, deadline);
        return txHash;
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }
}
