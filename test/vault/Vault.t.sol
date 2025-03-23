// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VaultTest is Test {
    StrategyEngine public engine;
    Vault public vault;
    IERC20 public usdc;
    HelperConfig public helperConfig;

    address public owner;
    address public user;
    address public signer1;
    uint256 public signer1Key;
    uint256 public deployerKey;

    event Deposit(address indexed token, uint256 amount);
    event Withdraw(address indexed token, uint256 amount);

    error OwnableUnauthorizedAccount(address account);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        (signer1, signer1Key) = makeAddrAndKey("signer1");

        DeployScript deployer = new DeployScript();
        (engine, , vault, helperConfig) = deployer.run();
        address usdcAddress;
        (, usdcAddress, , , , deployerKey, ) = helperConfig.activeNetworkConfig();
        usdc = IERC20(usdcAddress);
        owner = address(engine);

        // Deal some USDC to user
        deal(address(usdc), user, 1000e6);
    }

    function test_Initialize() public view {
        assertEq(vault.owner(), owner);
        assertEq(address(vault.token()), address(usdc));
    }

    function test_Deposit() public {
        uint256 amount = 100e6;
        vm.startPrank(user);
        usdc.approve(address(vault), amount);

        vm.expectEmit(true, true, true, true);
        emit Deposit(address(usdc), amount);
        vault.depositProfit(amount);

        assertEq(usdc.balanceOf(address(vault)), amount);
        assertEq(usdc.balanceOf(user), 900e6);
        vm.stopPrank();
    }

    function test_RevertWhen_DepositZero() public {
        vm.prank(user);
        vm.expectRevert(Vault.Vault__InvalidAmount.selector);
        vault.depositProfit(0);
    }

    function test_WithdrawThroughMultiSig() public {}

    function test_RevertWhen_WithdrawZero() public {
        vm.prank(user);
        vm.expectRevert(Vault.Vault__InvalidAmount.selector);
        vault.withdrawProfit(user, 0);
    }

    function test_RevertWhen_WithdrawTooMuch() public {}

    function test_RevertWhen_WithdrawUnauthorized() public {
        uint256 amount = 100e6;
        vm.startPrank(user);
        usdc.approve(address(vault), amount);
        vault.depositProfit(amount);
        vm.stopPrank();

        vm.prank(user);
        vm.expectRevert(Vault.Vault__Unauthorized.selector);
        vault.withdrawProfit(user, amount);
    }
}
