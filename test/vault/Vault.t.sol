// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VaultTest is Test {
    StrategyEngine public engine;
    Vault public vault;
    IERC20 public usdc;
    HelperConfig public helperConfig;
    MultiSig public multiSig;
    SignerManager public signerManager;

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
        (engine, , vault, signerManager, multiSig, helperConfig) = deployer.run();
        address usdcAddress;
        (, usdcAddress, , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
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

    function test_WithdrawThroughMultiSig() public {
        uint256 amount = 100e6;
        vm.startPrank(user);
        usdc.approve(address(vault), amount);
        vault.depositProfit(amount);
        vm.stopPrank();

        // Prepare multi-signature transaction data
        bytes memory data = abi.encodeWithSelector(Vault.withdrawProfit.selector, user, amount);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(address(multiSig), address(vault), data, 0, deadline);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.expectEmit(true, true, true, true);
        emit Withdraw(address(usdc), amount);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(vault), data, deadline, signatures);

        assertEq(usdc.balanceOf(address(vault)), 0);
        assertEq(usdc.balanceOf(user), 1000e6);
    }

    function test_RevertWhen_WithdrawZero() public {
        vm.prank(user);
        vm.expectRevert(Vault.Vault__InvalidAmount.selector);
        vault.withdrawProfit(user, 0);
    }

    function test_RevertWhen_WithdrawTooMuch() public {
        uint256 depositAmount = 100e6;
        uint256 withdrawAmount = 200e6;
        vm.startPrank(user);
        usdc.approve(address(vault), depositAmount);
        vault.depositProfit(depositAmount);
        vm.stopPrank();

        bytes memory data = abi.encodeWithSelector(
            Vault.withdrawProfit.selector,
            user,
            withdrawAmount
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = _hashTransaction(address(multiSig), address(vault), data, 0, deadline);

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);
        multiSig.executeTransaction(address(vault), data, deadline, signatures);
    }

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

    // Helper functions
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
