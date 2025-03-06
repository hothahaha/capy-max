// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {UserPosition} from "../../src/UserPosition.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {IStrategyEngine} from "../../src/interfaces/IStrategyEngine.sol";
import {IAaveOracle} from "../../src/aave/interface/IAaveOracle.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract StrategyEngineFuzzTest is Test {
    StrategyEngine public engine;
    CpToken public cpToken;
    Vault public vault;
    HelperConfig public helperConfig;

    address public wbtc;
    address public usdc;
    address public aaveOracle;
    uint256 public deployerKey;

    address public deployer;
    address public user1;
    address public user2;
    address public user3;

    uint256 public constant INITIAL_BALANCE = 22.9e8; // 22.9 WBTC
    uint256 public user1PrivateKey;
    uint256 public user2PrivateKey;
    uint256 public user3PrivateKey;

    function setUp() public {
        // Deploy contracts
        DeployScript deployScript = new DeployScript();
        (engine, cpToken, vault, , , helperConfig) = deployScript.run();

        // Get configuration
        (wbtc, usdc, , aaveOracle, , deployerKey, , ) = helperConfig.activeNetworkConfig();

        deployer = vm.addr(deployerKey);

        // 使用 makeAddrAndKey 获取地址和对应的私钥
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

    // 辅助函数：生成有效的签名
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

    // 辅助函数：执行WBTC存款
    function _depositWbtc(address user, uint256 amount, uint256 privateKey) internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IERC20Permit(wbtc).nonces(user);

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            amount,
            nonce,
            deadline,
            privateKey
        );

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

    // 辅助函数：执行USDC存款
    function _depositUsdc(address user, uint256 amount) internal {
        vm.prank(user);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            amount,
            0, // referralCode
            0, // deadline (不需要)
            0, // v (不需要)
            bytes32(0), // r (不需要)
            bytes32(0) // s (不需要)
        );
    }

    // 模糊测试：WBTC存款金额
    function testFuzz_WbtcDeposit(uint256 amount) public {
        // 约束金额在合理范围内
        amount = bound(amount, 1, INITIAL_BALANCE / 2);

        // 执行存款
        _depositWbtc(user1, amount, user1PrivateKey);

        // 验证存款结果
        (uint256 totalWbtc, , uint256 totalBorrows, ) = engine.getUserTotals(user1);
        assertEq(totalWbtc, amount, "WBTC deposit amount incorrect");
        assertGt(totalBorrows, 0, "Should have borrowed USDC");
    }

    // 模糊测试：USDC存款金额
    function testFuzz_UsdcDeposit(uint256 amount) public {
        // 约束金额在合理范围内
        amount = bound(amount, 1, INITIAL_BALANCE / 2);

        // 执行存款
        _depositUsdc(user2, amount);

        // 验证存款结果
        (, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(user2);
        assertEq(totalUsdc, amount, "USDC deposit amount incorrect");
        assertEq(totalBorrows, 0, "Should not have borrowed for USDC deposit");
    }

    // 模糊测试：多用户存款
    function testFuzz_MultipleUsersDeposit(
        uint256 amount1,
        uint256 amount2,
        uint256 amount3
    ) public {
        // 约束金额在合理范围内
        amount1 = bound(amount1, 1, INITIAL_BALANCE / 4);
        amount2 = bound(amount2, 1, INITIAL_BALANCE / 4);
        amount3 = bound(amount3, 1, INITIAL_BALANCE / 4);

        // 用户1存入WBTC
        _depositWbtc(user1, amount1, user1PrivateKey);

        // 用户2存入USDC
        _depositUsdc(user2, amount2);

        // 用户3存入WBTC
        _depositWbtc(user3, amount3, user3PrivateKey);

        // 验证所有用户的存款
        (uint256 totalWbtc1, , , ) = engine.getUserTotals(user1);
        assertEq(totalWbtc1, amount1, "User1 WBTC deposit amount incorrect");

        (, uint256 totalUsdc2, uint256 totalBorrows2, ) = engine.getUserTotals(user2);
        assertEq(totalUsdc2, amount2, "User2 USDC deposit amount incorrect");
        assertEq(totalBorrows2, 0, "User2 should not have borrowed");

        (uint256 totalWbtc3, , uint256 totalBorrows3, ) = engine.getUserTotals(user3);
        assertEq(totalWbtc3, amount3, "User3 WBTC deposit amount incorrect");
        assertGt(totalBorrows3, 0, "User3 should have borrowed USDC");
    }

    // 模糊测试：存款和提款
    function testFuzz_DepositAndWithdraw(uint256 amount) public {
        // 约束金额在合理范围内
        amount = bound(amount, 1e6, INITIAL_BALANCE / 2);

        // 用户存入USDC
        _depositUsdc(user1, amount);

        // 模拟利润返回
        uint256 profit = amount / 10; // 10% 利润
        deal(usdc, address(engine), amount + profit);

        // 执行提款
        vm.prank(user1);
        (uint256 userProfit, ) = engine.withdraw(
            StrategyEngine.TokenType.USDC,
            user1,
            amount + profit
        );

        // 验证提款结果
        assertGt(userProfit, 0, "User should receive profit");
        assertGt(cpToken.balanceOf(user1), 0, "User should receive reward tokens");

        // 验证平台费用
        uint256 platformFee = (profit * engine.getPlatformFee()) / 10000;
        assertGe(
            IERC20(usdc).balanceOf(address(vault)),
            platformFee,
            "Platform fee should be transferred to vault"
        );
    }

    // 模糊测试：平台费用更新
    function testFuzz_UpdatePlatformFee(uint256 newFee) public {
        // 约束费用在有效范围内 (0-100%)
        newFee = bound(newFee, 0, 10000);

        // 更新平台费用
        vm.prank(deployer);
        engine.updatePlatformFee(newFee);

        // 验证费用已更新
        assertEq(engine.getPlatformFee(), newFee, "Platform fee should be updated");
    }

    // 模糊测试：借款能力更新
    function testFuzz_UpdateBorrowCapacity(uint256 amount) public {
        // 约束金额在合理范围内
        amount = bound(amount, 1e8, INITIAL_BALANCE / 2);

        // 用户存入WBTC
        _depositWbtc(user1, amount, user1PrivateKey);

        // 获取初始借款金额
        (, , uint256 initialBorrowAmount, ) = engine.getUserTotals(user1);

        // 模拟BTC价格上涨50%
        uint256 originalPrice = engine.aaveOracle().getAssetPrice(address(wbtc));
        vm.mockCall(
            address(engine.aaveOracle()),
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, address(wbtc)),
            abi.encode((originalPrice * 3) / 2)
        );

        // 更新借款能力
        vm.prank(deployer);
        engine.updateBorrowCapacity(user1);

        // 验证借款能力已增加
        (, , uint256 newBorrowAmount, ) = engine.getUserTotals(user1);
        assertGt(
            newBorrowAmount,
            initialBorrowAmount,
            "Borrow capacity should increase after price increase"
        );
    }
}
