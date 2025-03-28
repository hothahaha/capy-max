// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {UserPosition} from "../../src/UserPosition.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {IStrategyEngine} from "../../src/interfaces/IStrategyEngine.sol";
import {IAaveOracle} from "../../src/interfaces/aave/IAaveOracle.sol";
import {ISafe} from "../../src/interfaces/safe/ISafe.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract StrategyEngineIntegrationTest is Test {
    StrategyEngine public engine;
    CpToken public cpToken;
    Vault public vault;
    HelperConfig public helperConfig;

    address public wbtc;
    address public usdc;
    address public aaveOracle;
    uint256 public deployerKey;

    address public DEPLOYER;
    address public user1;
    address public user2;
    address public user3;

    uint256 public constant WBTC_AMOUNT = 1e8; // 1 WBTC
    uint256 public constant USDC_AMOUNT = 10_000e6; // 10,000 USDC
    uint256 public constant INITIAL_BALANCE = 100_000e6; // 100,000 USDC/WBTC

    uint256 public user1PrivateKey;
    uint256 public user2PrivateKey;
    uint256 public user3PrivateKey;

    function setUp() public {
        // Deploy contracts
        DeployScript deployScript = new DeployScript();
        (engine, cpToken, vault, helperConfig) = deployScript.run();

        address safeWallet;
        address[] memory safeSigners;

        // Get configuration
        (wbtc, usdc, , aaveOracle, , deployerKey, safeWallet) = helperConfig.activeNetworkConfig();

        DEPLOYER = vm.addr(deployerKey);

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

        // Use makeAddrAndKey to get addresses and corresponding private keys
        (user1, user1PrivateKey) = makeAddrAndKey("user1");
        (user2, user2PrivateKey) = makeAddrAndKey("user2");
        (user3, user3PrivateKey) = makeAddrAndKey("user3");

        // Assign tokens to test users
        deal(wbtc, user1, INITIAL_BALANCE);
        deal(usdc, user1, INITIAL_BALANCE);
        deal(wbtc, user2, INITIAL_BALANCE);
        deal(usdc, user2, INITIAL_BALANCE);
        deal(wbtc, user3, INITIAL_BALANCE);
        deal(usdc, user3, INITIAL_BALANCE);

        // Simulate user authorization
        vm.startPrank(user1);
        IERC20(wbtc).approve(address(engine), type(uint256).max);
        IERC20(usdc).approve(address(engine), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(user2);
        IERC20(wbtc).approve(address(engine), type(uint256).max);
        IERC20(usdc).approve(address(engine), type(uint256).max);
        vm.stopPrank();

        vm.startPrank(user3);
        IERC20(wbtc).approve(address(engine), type(uint256).max);
        IERC20(usdc).approve(address(engine), type(uint256).max);
        vm.stopPrank();
    }

    // Test creating user position
    function testCreateUserPosition() public {
        vm.prank(user1);
        engine.createUserPosition();

        address userPosition = engine.getUserPositionAddress(user1);
        assertNotEq(userPosition, address(0), "User position should be created");
    }

    // Test WBTC deposit process
    function testWbtcDeposit() public {
        uint256 initialWbtcBalance = IERC20(wbtc).balanceOf(user1);

        // Simulate permit signature
        _depositWbtcWithPermit(user1, WBTC_AMOUNT, user1PrivateKey);

        // Verify user position has been created
        address userPosition = engine.getUserPositionAddress(user1);
        assertNotEq(userPosition, address(0), "User position should be created");

        // Verify user information has been updated
        (uint256 totalWbtc, , uint256 totalBorrows, ) = engine.getUserTotals(user1);
        assertEq(totalWbtc, WBTC_AMOUNT, "WBTC deposit amount incorrect");
        assertGt(totalBorrows, 0, "Should have borrowed USDC");

        // Verify user WBTC balance has been reduced
        assertEq(
            IERC20(wbtc).balanceOf(user1),
            initialWbtcBalance - WBTC_AMOUNT,
            "WBTC not transferred"
        );
    }

    // Test USDC deposit process
    function testUsdcDeposit() public {
        uint256 initialUsdcBalance = IERC20(usdc).balanceOf(user2);

        // Execute deposit
        vm.prank(user2);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            USDC_AMOUNT,
            0, // referralCode
            0, // deadline (not needed)
            0, // v (not needed)
            bytes32(0), // r (not needed)
            bytes32(0) // s (not needed)
        );

        // Verify user information has been updated
        (, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(user2);
        assertEq(totalUsdc, USDC_AMOUNT, "USDC deposit amount incorrect");
        assertEq(totalBorrows, 0, "Should not have borrowed for USDC deposit");

        // Verify user USDC balance has been reduced
        assertEq(
            IERC20(usdc).balanceOf(user2),
            initialUsdcBalance - USDC_AMOUNT,
            "USDC not transferred"
        );
    }

    // Test multiple users and borrow capacity update
    function testMultipleUsersAndBorrowCapacity() public {
        // User 1 deposits WBTC
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce1 = IERC20Permit(wbtc).nonces(user1);
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user1,
            address(engine),
            WBTC_AMOUNT,
            nonce1,
            deadline,
            user1PrivateKey
        );

        vm.prank(user1);
        engine.deposit(StrategyEngine.TokenType.WBTC, WBTC_AMOUNT, 0, deadline, v, r, s);

        // User 2 deposits USDC
        vm.prank(user2);
        engine.deposit(StrategyEngine.TokenType.USDC, USDC_AMOUNT, 0, 0, 0, bytes32(0), bytes32(0));

        // User 3 deposits WBTC
        uint256 nonce3 = IERC20Permit(wbtc).nonces(user3);
        (v, r, s) = _getPermitSignature(
            wbtc,
            user3,
            address(engine),
            WBTC_AMOUNT,
            nonce3,
            deadline,
            user3PrivateKey
        );

        vm.prank(user3);
        engine.deposit(StrategyEngine.TokenType.WBTC, WBTC_AMOUNT, 0, deadline, v, r, s);

        // Simulate BTC price increase
        uint256 originalPrice = IAaveOracle(engine.getAaveOracleAddress()).getAssetPrice(
            address(wbtc)
        );
        vm.mockCall(
            engine.getAaveOracleAddress(),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice * 2)
        );

        // Update user 1's borrow capacity
        vm.prank(DEPLOYER);
        engine.updateBorrowCapacity(user1);

        // Verify borrow capacity has been updated
        (, , uint256 totalBorrows1After, ) = engine.getUserTotals(user1);
        assertGt(totalBorrows1After, 0, "Borrow capacity should be updated");
    }

    // Test withdrawal process
    function testWithdraw() public {
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

    // Test health check and batch processing
    function testHealthCheck() public {
        // Create multiple user positions
        for (uint256 i = 1; i <= 25; i++) {
            (address user, uint256 userPrivateKey) = makeAddrAndKey(
                string(abi.encodePacked("healthUser", i))
            );
            deal(wbtc, user, INITIAL_BALANCE);

            vm.prank(user);
            IERC20(wbtc).approve(address(engine), type(uint256).max);

            uint256 deadline = block.timestamp + 1 days;
            uint256 nonce = IERC20Permit(wbtc).nonces(user);

            (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
                wbtc,
                user,
                address(engine),
                WBTC_AMOUNT,
                nonce,
                deadline,
                userPrivateKey
            );

            vm.prank(user);
            engine.deposit(StrategyEngine.TokenType.WBTC, WBTC_AMOUNT, 0, deadline, v, r, s);
        }

        // Fast forward time
        vm.warp(block.timestamp + 2 hours);

        // Execute health check
        engine.scheduledHealthCheck();

        // Verify batch index has been updated
        assertEq(engine.currentBatchIndex(), 10, "Batch index should be updated");

        // Execute health check again
        engine.scheduledHealthCheck();

        // Verify batch index has been updated to second batch
        assertEq(engine.currentBatchIndex(), 20, "Batch index should be updated to second batch");

        // Execute scheduled health check again
        engine.scheduledHealthCheck();

        // Verify batch index has been reset
        assertEq(
            engine.currentBatchIndex(),
            0,
            "Batch index should be reset after processing all users"
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

    // Test repay borrow in emergency
    function testRepayBorrow() public {
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

        // Verify repayment
        (, , uint256 newBorrows, ) = engine.getUserTotals(user2);
        assertEq(newBorrows, 0, "Should have no borrows after repayment");
    }

    // Test extreme case: attempt to withdraw more than the deposit amount
    function testFailWithdrawTooMuch() public {
        // User 2 deposits USDC
        vm.prank(user2);
        engine.deposit(StrategyEngine.TokenType.USDC, USDC_AMOUNT, 0, 0, 0, bytes32(0), bytes32(0));

        // Prepare withdrawal parameters with excessive amount
        address[] memory users = new address[](1);
        uint256[] memory amounts = new uint256[](1);
        users[0] = user2;
        amounts[0] = USDC_AMOUNT * 2;

        // Try to withdraw more than the deposit amount
        vm.prank(user2);
        engine.withdrawBatch(users, amounts);
        // Should fail because the amount exceeds the deposit
    }

    // Test update platform fee
    function testUpdatePlatformFee() public {
        uint256 initialFee = engine.getPlatformFee();
        uint256 newFee = 1500; // 15%

        // Update platform fee
        vm.prank(DEPLOYER);
        engine.updatePlatformFee(newFee);

        // Verify fee has been updated
        assertEq(engine.getPlatformFee(), newFee, "Platform fee should be updated");
        assertNotEq(
            engine.getPlatformFee(),
            initialFee,
            "Platform fee should be different from initial"
        );
    }

    // Test price crash scenario
    /* function testPriceCrash() public {
        // User deposits WBTC
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IERC20Permit(wbtc).nonces(user1);
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user1,
            address(engine),
            WBTC_AMOUNT,
            nonce,
            deadline,
            user1PrivateKey
        );

        vm.prank(user1);
        engine.deposit(StrategyEngine.TokenType.WBTC, WBTC_AMOUNT, 0, deadline, v, r, s);

        // Get initial borrow amount
        (, , uint256 initialBorrowAmount, ) = engine.getUserTotals(user1);

        // Simulate BTC price crash 50%
        uint256 originalPrice = IAaveOracle(engine.getAaveOracleAddress()).getAssetPrice(
            address(wbtc)
        );
        vm.mockCall(
            engine.getAaveOracleAddress(),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice / 2)
        );

        // Update borrow capacity
        vm.prank(DEPLOYER);
        engine.updateBorrowCapacity(user1);

        // Verify borrow capacity has decreased
        (, , uint256 newBorrowAmount, ) = engine.getUserTotals(user1);
        assertEq(
            newBorrowAmount,
            initialBorrowAmount,
            "capacity should not change beacuse only log is updated"
        );

        // Simulate price recovery
        vm.mockCall(
            engine.getAaveOracleAddress(),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode(originalPrice)
        );

        // Update borrow capacity again
        vm.prank(DEPLOYER);
        engine.updateBorrowCapacity(user1);

        // Verify borrow capacity has recovered
        (, , uint256 recoveredBorrowAmount, ) = engine.getUserTotals(user1);
        assertEq(
            recoveredBorrowAmount,
            initialBorrowAmount,
            "Borrow capacity should recover after price recovery"
        );
    } */

    // Test mass withdrawal
    function testMassWithdrawal() public {
        // Create multiple users and deposit
        address[] memory users = new address[](20);
        uint256[] memory privateKeys = new uint256[](20);
        uint256[] memory userBorrows = new uint256[](20);

        // 1. Create users and deposit
        for (uint256 i = 0; i < 20; i++) {
            (address user, uint256 userPrivateKey) = makeAddrAndKey(
                string(abi.encodePacked("massUser", i))
            );
            users[i] = user;
            privateKeys[i] = userPrivateKey;

            // Allocate tokens
            deal(wbtc, user, INITIAL_BALANCE);

            // Authorize
            vm.prank(user);
            IERC20(wbtc).approve(address(engine), type(uint256).max);

            // Deposit
            uint256 deadline = block.timestamp + 1 days;
            uint256 nonce = IERC20Permit(wbtc).nonces(user);

            (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
                wbtc,
                user,
                address(engine),
                WBTC_AMOUNT,
                nonce,
                deadline,
                userPrivateKey
            );

            vm.prank(user);
            engine.deposit(StrategyEngine.TokenType.WBTC, WBTC_AMOUNT, 0, deadline, v, r, s);

            // Record borrow amount
            (, , userBorrows[i], ) = engine.getUserTotals(user);
        }

        // 2. Calculate total borrow amount and profit
        uint256 totalBorrowAmount = 0;
        for (uint256 i = 0; i < 20; i++) {
            totalBorrowAmount += userBorrows[i];
        }

        uint256 profit = totalBorrowAmount / 5; // 20% profit
        deal(usdc, address(engine), totalBorrowAmount + profit);

        // 3. All users withdraw at the same time
        for (uint256 i = 0; i < 20; i++) {
            address[] memory withdrawUsers = new address[](1);
            uint256[] memory amounts = new uint256[](1);

            withdrawUsers[0] = users[i];
            amounts[0] = userBorrows[i] + (profit / 20); // 平均分配利润

            vm.prank(DEPLOYER);
            engine.withdrawBatch(withdrawUsers, amounts);

            // Verify each user's withdrawal result
            (uint256 wbtcBalance, , uint256 borrowBalance, ) = engine.getUserTotals(users[i]);
            assertEq(wbtcBalance, 0, "User should have withdrawn all WBTC");
            assertEq(borrowBalance, 0, "User should have repaid all borrows");
        }

        // 4. Verify contract state
        assertEq(IERC20(wbtc).balanceOf(address(engine)), 0, "Contract should have no WBTC left");
    }

    // Test extreme deposit amounts
    function testExtremeDepositAmounts() public {
        // Test minimum possible deposit
        uint256 minDeposit = 1; // 1 satoshi
        deal(wbtc, user1, minDeposit);

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IERC20Permit(wbtc).nonces(user1);
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user1,
            address(engine),
            minDeposit,
            nonce,
            deadline,
            user1PrivateKey
        );

        vm.prank(user1);
        engine.deposit(StrategyEngine.TokenType.WBTC, minDeposit, 0, deadline, v, r, s);

        // Verify minimum deposit is processed
        (uint256 wbtcBalance, , , ) = engine.getUserTotals(user1);
        assertEq(wbtcBalance, minDeposit, "Minimum deposit should be processed");

        // Test maximum deposit
        uint256 maxDeposit = 22e8; // 22 BTC
        deal(wbtc, user2, maxDeposit);

        nonce = IERC20Permit(wbtc).nonces(user2);
        (v, r, s) = _getPermitSignature(
            wbtc,
            user2,
            address(engine),
            maxDeposit,
            nonce,
            deadline,
            user2PrivateKey
        );

        vm.prank(user2);
        engine.deposit(StrategyEngine.TokenType.WBTC, maxDeposit, 0, deadline, v, r, s);

        // Verify maximum deposit is processed
        (wbtcBalance, , , ) = engine.getUserTotals(user2);
        assertEq(wbtcBalance, maxDeposit, "Maximum deposit should be processed");
    }

    // Test update borrow capacity
    function testUpdateBorrowCapacity() public {
        // Deploy user position
        vm.prank(user1);
        engine.createUserPosition();

        // Verify position was created
        address user1Position = engine.getUserPositionAddress(user1);
        assertNotEq(user1Position, address(0), "User position should be created");

        // Deploy second user position
        vm.prank(user2);
        engine.createUserPosition();
        address user2Position = engine.getUserPositionAddress(user2);
        assertNotEq(user2Position, address(0), "User2 position should be created");
    }

    function _depositWbtcWithPermit(address user, uint256 amount, uint256 privateKey) internal {
        // Simulate permit signature
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IERC20Permit(wbtc).nonces(user);

        // Use the correct signature generation method
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            amount,
            nonce,
            deadline,
            privateKey
        );

        // Execute deposit
        vm.prank(user);
        engine.deposit(
            StrategyEngine.TokenType.WBTC,
            amount,
            0, // referralCode
            deadline,
            v,
            r,
            s
        );
    }
}

// Reentrancy attack contract
contract ReentrancyAttacker {
    StrategyEngine private engine;
    IERC20 private wbtc;
    IERC20 private usdc;
    bool private attacking;

    constructor(address _engine, address _wbtc, address _usdc) {
        engine = StrategyEngine(_engine);
        wbtc = IERC20(_wbtc);
        usdc = IERC20(_usdc);
        attacking = false;
    }

    // Callback when receiving ETH - for specific reentrancy attacks
    receive() external payable {
        if (!attacking) {
            attacking = true;

            // Create withdrawal info
            address[] memory users = new address[](1);
            uint256[] memory amounts = new uint256[](1);
            users[0] = address(this);
            amounts[0] = 500e6;

            try engine.withdrawBatch(users, amounts) {
                // Success indicates reentrancy protection failure
            } catch {
                // Failure indicates reentrancy protection works
            }
            attacking = false;
        }
    }
}
