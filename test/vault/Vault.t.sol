// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {AaveV3ArbitrumAssets} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

contract VaultTest is Test {
    Vault public vault;
    address public constant USDC = AaveV3ArbitrumAssets.USDC_UNDERLYING;
    address public owner;
    address public user;
    address public authorizedUser;

    uint256 public constant INITIAL_BALANCE = 1000e6; // 1000 USDC

    event ProfitDeposited(uint256 amount);
    event ProfitWithdrawn(address indexed to, uint256 amount);
    event AuthorizationUpdated(address indexed user, bool status);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        authorizedUser = makeAddr("authorizedUser");

        vm.startPrank(owner);
        // Deploy implementation and proxy
        Vault vaultImpl = new Vault();
        ERC1967Proxy vaultProxy = new ERC1967Proxy(
            address(vaultImpl),
            abi.encodeWithSelector(Vault.initialize.selector, USDC)
        );
        vault = Vault(address(vaultProxy));
        vault.setAuthorization(authorizedUser, true);
        vm.stopPrank();

        // 给 vault 和用户铸造 USDC
        deal(USDC, address(vault), INITIAL_BALANCE);
        deal(USDC, user, INITIAL_BALANCE);
    }

    function test_Constructor() public view {
        assertEq(address(vault.token()), USDC, "Incorrect token address");
        assertEq(vault.owner(), owner, "Incorrect owner");
    }

    function test_SetAuthorization() public {
        vm.startPrank(owner);

        // 测试授权
        vm.expectEmit(true, true, true, true);
        emit AuthorizationUpdated(user, true);
        vault.setAuthorization(user, true);
        assertTrue(vault.authorized(user), "User should be authorized");

        // 测试取消授权
        vm.expectEmit(true, true, true, true);
        emit AuthorizationUpdated(user, false);
        vault.setAuthorization(user, false);
        assertFalse(vault.authorized(user), "User should not be authorized");

        vm.stopPrank();
    }

    function testFail_SetAuthorizationNotOwner() public {
        vm.prank(user);
        vault.setAuthorization(user, true);
    }

    function test_DepositProfit() public {
        uint256 depositAmount = 100e6;
        uint256 beforeBalance = IERC20(USDC).balanceOf(address(vault));

        vm.startPrank(user);
        IERC20(USDC).approve(address(vault), depositAmount);

        vm.expectEmit(true, true, true, true);
        emit ProfitDeposited(depositAmount);
        vault.depositProfit(depositAmount);

        uint256 afterBalance = IERC20(USDC).balanceOf(address(vault));
        assertEq(
            afterBalance,
            beforeBalance + depositAmount,
            "Incorrect vault balance after deposit"
        );

        vm.stopPrank();
    }

    function testFail_DepositZeroAmount() public {
        vm.prank(user);
        vault.depositProfit(0);
    }

    function testFail_DepositWithoutApproval() public {
        vm.prank(user);
        vault.depositProfit(100e6);
    }

    function test_WithdrawProfit() public {
        uint256 withdrawAmount = 100e6;
        uint256 beforeVaultBalance = IERC20(USDC).balanceOf(address(vault));
        uint256 beforeUserBalance = IERC20(USDC).balanceOf(user);

        vm.prank(authorizedUser);
        vm.expectEmit(true, true, true, true);
        emit ProfitWithdrawn(user, withdrawAmount);
        vault.withdrawProfit(user, withdrawAmount);

        uint256 afterVaultBalance = IERC20(USDC).balanceOf(address(vault));
        uint256 afterUserBalance = IERC20(USDC).balanceOf(user);

        assertEq(
            afterVaultBalance,
            beforeVaultBalance - withdrawAmount,
            "Incorrect vault balance after withdrawal"
        );
        assertEq(
            afterUserBalance,
            beforeUserBalance + withdrawAmount,
            "Incorrect user balance after withdrawal"
        );
    }

    function testFail_WithdrawZeroAmount() public {
        vm.prank(authorizedUser);
        vault.withdrawProfit(user, 0);
    }

    function testFail_WithdrawUnauthorized() public {
        vm.prank(user);
        vault.withdrawProfit(user, 100e6);
    }

    function testFail_WithdrawInsufficientBalance() public {
        uint256 excessiveAmount = INITIAL_BALANCE + 1e6;
        vm.prank(authorizedUser);
        vault.withdrawProfit(user, excessiveAmount);
    }

    function test_OwnerCanWithdraw() public {
        uint256 withdrawAmount = 100e6;

        vm.prank(owner);
        vault.withdrawProfit(user, withdrawAmount);

        assertEq(
            IERC20(USDC).balanceOf(user),
            INITIAL_BALANCE + withdrawAmount,
            "Owner should be able to withdraw"
        );
    }

    function test_MultipleAuthorizedUsers() public {
        address authorizedUser2 = makeAddr("authorizedUser2");

        vm.startPrank(owner);
        vault.setAuthorization(authorizedUser2, true);
        vm.stopPrank();

        uint256 withdrawAmount = 50e6;

        // 第一个授权用户提取
        vm.prank(authorizedUser);
        vault.withdrawProfit(user, withdrawAmount);

        // 第二个授权用户提取
        vm.prank(authorizedUser2);
        vault.withdrawProfit(user, withdrawAmount);

        assertEq(
            IERC20(USDC).balanceOf(user),
            INITIAL_BALANCE + withdrawAmount * 2,
            "Both authorized users should be able to withdraw"
        );
    }
}
