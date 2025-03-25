// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract VaultTest is Test {
    StrategyEngine public engine;
    Vault public vault;
    IERC20 public usdc;
    HelperConfig public helperConfig;

    address public owner;
    address public user;
    address public safeWallet;
    address public recipient;
    uint256 public deployerKey;

    uint256 public constant INITIAL_BALANCE = 1000e6; // 1000 USDC

    event Deposit(address indexed token, uint256 amount);
    event Withdraw(address indexed token, uint256 amount);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        recipient = makeAddr("recipient");

        DeployScript deployer = new DeployScript();
        (engine, , vault, helperConfig) = deployer.run();
        address usdcAddress;
        (, usdcAddress, , , , deployerKey, safeWallet) = helperConfig.activeNetworkConfig();
        usdc = IERC20(usdcAddress);
        owner = address(engine);

        // Deal some USDC to user
        deal(address(usdc), user, INITIAL_BALANCE);
        // Give Safe Wallet some ETH for transaction execution
        vm.deal(safeWallet, 1 ether);
    }

    function test_Initialize() public view {
        assertEq(vault.owner(), owner);
        assertEq(address(vault.token()), address(usdc));
        assertEq(vault.safeWallet(), safeWallet);
    }

    function test_Deposit() public {
        uint256 amount = 100e6;
        vm.startPrank(user);
        usdc.approve(address(vault), amount);

        vm.expectEmit(true, true, true, true);
        emit Deposit(address(usdc), amount);
        vault.depositProfit(amount);

        assertEq(usdc.balanceOf(address(vault)), amount);
        assertEq(usdc.balanceOf(user), INITIAL_BALANCE - amount);
        vm.stopPrank();
    }

    function test_RevertWhen_DepositZero() public {
        vm.prank(user);
        vm.expectRevert(Vault.Vault__InvalidAmount.selector);
        vault.depositProfit(0);
    }

    function test_WithdrawThroughMultiSig() public {
        // 1. First deposit funds
        uint256 depositAmount = 500e6;
        vm.startPrank(user);
        usdc.approve(address(vault), depositAmount);
        vault.depositProfit(depositAmount);
        vm.stopPrank();

        // Confirm deposit was successful
        assertEq(usdc.balanceOf(address(vault)), depositAmount);

        // 2. Withdraw funds through Safe wallet
        uint256 withdrawAmount = 200e6;
        vm.prank(safeWallet);

        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(usdc), withdrawAmount);
        vault.withdrawProfit(recipient, withdrawAmount);

        // Verify funds were transferred
        assertEq(usdc.balanceOf(address(vault)), depositAmount - withdrawAmount);
        assertEq(usdc.balanceOf(recipient), withdrawAmount);
    }

    function test_RevertWhen_WithdrawZero() public {
        vm.prank(safeWallet);
        vm.expectRevert(Vault.Vault__InvalidAmount.selector);
        vault.withdrawProfit(user, 0);
    }

    function test_RevertWhen_WithdrawTooMuch() public {
        // 1. First deposit funds
        uint256 depositAmount = 100e6;
        vm.startPrank(user);
        usdc.approve(address(vault), depositAmount);
        vault.depositProfit(depositAmount);
        vm.stopPrank();

        // 2. Try to withdraw more than the balance
        uint256 withdrawAmount = 200e6; // Exceeds balance
        vm.prank(safeWallet);
        vm.expectRevert(Vault.Vault__InsufficientBalance.selector);
        vault.withdrawProfit(recipient, withdrawAmount);
    }

    function test_RevertWhen_WithdrawUnauthorized() public {
        uint256 amount = 100e6;
        vm.startPrank(user);
        usdc.approve(address(vault), amount);
        vault.depositProfit(amount);
        vm.stopPrank();

        vm.prank(user); // Not the Safe wallet
        vm.expectRevert(Vault.Vault__Unauthorized.selector);
        vault.withdrawProfit(user, amount);
    }

    function test_GetBalance() public {
        // Initial balance should be 0
        assertEq(vault.getBalance(), 0);

        // Deposit funds
        uint256 depositAmount = 150e6;
        vm.startPrank(user);
        usdc.approve(address(vault), depositAmount);
        vault.depositProfit(depositAmount);
        vm.stopPrank();

        // Balance should be updated
        assertEq(vault.getBalance(), depositAmount);

        // Withdraw partial funds
        uint256 withdrawAmount = 50e6;
        vm.prank(safeWallet);
        vault.withdrawProfit(recipient, withdrawAmount);

        // Balance should decrease
        assertEq(vault.getBalance(), depositAmount - withdrawAmount);
    }

    function test_DepositAndWithdrawMultipleTimes() public {
        // Multiple deposits and withdrawals to test contract state consistency
        uint256 firstDeposit = 100e6;
        uint256 secondDeposit = 200e6;
        uint256 firstWithdraw = 50e6;
        uint256 secondWithdraw = 150e6;

        // First deposit
        vm.startPrank(user);
        usdc.approve(address(vault), firstDeposit + secondDeposit);
        vault.depositProfit(firstDeposit);
        assertEq(vault.getBalance(), firstDeposit);

        // Second deposit
        vault.depositProfit(secondDeposit);
        assertEq(vault.getBalance(), firstDeposit + secondDeposit);
        vm.stopPrank();

        // First withdrawal
        vm.prank(safeWallet);
        vault.withdrawProfit(recipient, firstWithdraw);
        assertEq(vault.getBalance(), firstDeposit + secondDeposit - firstWithdraw);
        assertEq(usdc.balanceOf(recipient), firstWithdraw);

        // Second withdrawal
        vm.prank(safeWallet);
        vault.withdrawProfit(recipient, secondWithdraw);
        assertEq(vault.getBalance(), firstDeposit + secondDeposit - firstWithdraw - secondWithdraw);
        assertEq(usdc.balanceOf(recipient), firstWithdraw + secondWithdraw);
    }

    function test_DepositExactBalance() public {
        // Test user depositing their entire balance
        uint256 userBalance = usdc.balanceOf(user);

        vm.startPrank(user);
        usdc.approve(address(vault), userBalance);
        vault.depositProfit(userBalance);
        vm.stopPrank();

        // Verify user balance is 0 and Vault received all funds
        assertEq(usdc.balanceOf(user), 0, "User balance should be 0");
        assertEq(
            vault.getBalance(),
            userBalance,
            "Vault balance should equal user's previous balance"
        );
    }

    function test_WithdrawToMultipleRecipients() public {
        // Test withdrawing funds to multiple different recipients
        address recipient1 = makeAddr("recipient1");
        address recipient2 = makeAddr("recipient2");

        // Deposit
        uint256 depositAmount = 300e6;
        vm.startPrank(user);
        usdc.approve(address(vault), depositAmount);
        vault.depositProfit(depositAmount);
        vm.stopPrank();

        // Withdraw to first recipient
        uint256 withdraw1 = 100e6;
        vm.prank(safeWallet);
        vault.withdrawProfit(recipient1, withdraw1);
        assertEq(usdc.balanceOf(recipient1), withdraw1);

        // Withdraw to second recipient
        uint256 withdraw2 = 150e6;
        vm.prank(safeWallet);
        vault.withdrawProfit(recipient2, withdraw2);
        assertEq(usdc.balanceOf(recipient2), withdraw2);

        // Verify Vault balance is correct
        assertEq(vault.getBalance(), depositAmount - withdraw1 - withdraw2);
    }

    function test_DirectDeployAndInitialize() public {
        // Manually deploy and initialize Vault, testing proxy contract logic
        Vault vaultImplementation = new Vault();

        bytes memory initData = abi.encodeWithSelector(
            Vault.initialize.selector,
            address(usdc),
            safeWallet
        );

        ERC1967Proxy proxy = new ERC1967Proxy(address(vaultImplementation), initData);
        Vault newVault = Vault(address(proxy));

        // Verify initialization parameters
        assertEq(address(newVault.token()), address(usdc));
        assertEq(newVault.safeWallet(), safeWallet);

        // Test functionality
        uint256 amount = 100e6;
        deal(address(usdc), address(this), amount);
        usdc.approve(address(newVault), amount);
        newVault.depositProfit(amount);

        assertEq(usdc.balanceOf(address(newVault)), amount);
    }
}
