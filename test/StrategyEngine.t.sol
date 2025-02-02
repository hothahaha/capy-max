// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

import {IAavePool} from "../src/aave/interface/IAavePool.sol";
import {IVariableDebtToken} from "../src/aave/interface/IVariableDebtToken.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {UserPosition} from "../src/UserPosition.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";

contract StrategyEngineTest is Test {
    IAavePool public aavePool;
    StrategyEngine public engine;
    address public wbtc;
    address public usdc;
    address public USER;
    uint256 public USER_PRIVATE_KEY;
    uint256 public constant INITIAL_ETH_BALANCE = 10 ether;
    uint256 public constant INITIAL_WBTC_BALANCE = 1000e8;
    uint256 public constant GMX_EXECUTION_FEE = 0.011 ether;
    uint256 public constant HEALTH_FACTOR_THRESHOLD = 1e19; // 1.0

    // GMX related addresses
    address public constant GMX_ROUTER =
        0x7C68C7866A64FA2160F78EEaE12217FFbf871fa8;
    address public constant GMX_ROUTER_PLUGIN =
        0x7452c558d45f8afC8c83dAe62C3f8A5BE19c71f6;
    bytes32 public constant ROUTER_PLUGIN_ROLE = keccak256("ROUTER_PLUGIN");

    function setUp() public {
        DeployScript deployer = new DeployScript();
        HelperConfig config = new HelperConfig();
        (engine, , config) = deployer.run();
        (wbtc, usdc, ) = config.activeNetworkConfig();

        (USER, USER_PRIVATE_KEY) = makeAddrAndKey("user");

        // Deal ETH and tokens to user
        vm.deal(USER, INITIAL_ETH_BALANCE);
        deal(wbtc, USER, INITIAL_WBTC_BALANCE);
    }

    function test_DepositWBTC() public {
        uint256 amount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        // Get current nonce for the user
        uint256 nonce = IERC20Permit(wbtc).nonces(USER);

        // Generate signature for deposit
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            USER,
            address(engine),
            amount,
            nonce,
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(USER);

        // 记录存款前的余额
        uint256 beforeWbtcBalance = IERC20(wbtc).balanceOf(USER);

        // 执行存款
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            amount,
            0,
            deadline,
            v,
            r,
            s
        );

        // 验证存款后状态
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine
            .getUserTotals(USER);

        // 验证 WBTC 存款金额
        assertEq(totalWbtc, amount, "Incorrect WBTC deposit amount");
        assertEq(totalUsdc, 0, "USDC amount should be zero");

        // 验证借贷金额
        assertGt(totalBorrows, 0, "Should have borrowed USDC");

        // 验证用户余额变化
        assertEq(
            IERC20(wbtc).balanceOf(USER),
            beforeWbtcBalance - amount,
            "Incorrect WBTC balance change"
        );

        (
            ,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            ,
            ,
            uint256 healthFactor
        ) = engine.getUserAccountData(USER);

        assertGt(totalDebtBase, 0, "Should have borrowed USDC");
        assertGt(availableBorrowsBase, 0, "Should have available borrows");
        assertLt(healthFactor, 1e27, "Health factor should be less than 1");

        // 验证存款记录
        StrategyEngine.DepositRecord[] memory records = engine
            .getUserDepositRecords(USER);
        assertEq(records.length, 1, "Should have one deposit record");
        assertEq(
            uint8(records[0].tokenType),
            uint8(StrategyEngine.TokenType.WBTC),
            "Incorrect token type"
        );
        assertEq(records[0].amount, amount, "Incorrect record amount");
        assertGt(
            records[0].borrowAmount,
            0,
            "Should have borrow amount in record"
        );

        // 验证健康因子
        (, , , , , uint256 healthFactorAfterDeposit) = engine
            .getUserAccountData(USER);
        assertLt(
            healthFactorAfterDeposit,
            HEALTH_FACTOR_THRESHOLD,
            "Health factor should be less than threshold after deposit and borrow"
        );

        vm.stopPrank();
    }

    function test_DepositUSDC() public {
        uint256 amount = 1000e6; // 1000 USDC

        vm.startPrank(USER);

        // 给用户铸造 USDC
        deal(address(usdc), USER, amount);

        // 记录存款前的余额
        uint256 beforeUsdcBalance = IERC20(usdc).balanceOf(USER);
        uint256 beforeCpTokenBalance = engine.cpToken().balanceOf(USER);

        // 授权并存款
        IERC20(usdc).approve(address(engine), amount);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            amount,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );

        // 验证存款后状态
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine
            .getUserTotals(USER);

        // 验证存款金额
        assertEq(totalUsdc, amount, "Incorrect USDC deposit amount");
        assertEq(totalWbtc, 0, "WBTC amount should be zero");
        assertEq(totalBorrows, 0, "Should not have any borrows");

        // 验证用户余额变化
        assertEq(
            IERC20(usdc).balanceOf(USER),
            beforeUsdcBalance - amount,
            "Incorrect USDC balance change"
        );

        // 验证 cpToken 未铸造
        assertEq(
            engine.cpToken().balanceOf(USER),
            beforeCpTokenBalance,
            "Should not mint cpToken for USDC deposit"
        );

        // 验证存款记录
        StrategyEngine.DepositRecord[] memory records = engine
            .getUserDepositRecords(USER);
        assertEq(records.length, 1, "Should have one deposit record");
        assertEq(
            uint8(records[0].tokenType),
            uint8(StrategyEngine.TokenType.USDC),
            "Incorrect token type"
        );
        assertEq(records[0].amount, amount, "Incorrect record amount");
        assertEq(
            records[0].borrowAmount,
            0,
            "Should not have borrow amount in record"
        );

        vm.stopPrank();
    }

    function testFail_DepositZeroAmount() public {
        vm.startPrank(USER);

        engine.deposit(
            StrategyEngine.TokenType.USDC,
            0,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );

        vm.stopPrank();
    }

    function testFail_DepositWithoutApproval() public {
        uint256 amount = 1000e6;

        vm.startPrank(USER);
        deal(address(usdc), USER, amount);

        // 不进行授权，直接存款
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            amount,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );

        vm.stopPrank();
    }

    function test_DepositWithExactBalance() public {
        uint256 amount = 1000e6;

        vm.startPrank(USER);

        // 给用户铸造精确数量的 USDC
        deal(address(usdc), USER, amount);
        IERC20(usdc).approve(address(engine), amount);

        // 存入全部余额
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            amount,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );

        // 验证余额为 0
        assertEq(
            IERC20(usdc).balanceOf(USER),
            0,
            "User balance should be zero"
        );

        vm.stopPrank();
    }

    // 添加存款 modifier
    modifier withWBTCDeposit() {
        uint256 depositAmount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            USER,
            address(engine),
            depositAmount,
            IERC20Permit(wbtc).nonces(USER),
            deadline,
            USER_PRIVATE_KEY
        );

        vm.startPrank(USER);

        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            depositAmount,
            0,
            deadline,
            v,
            r,
            s
        );
        _;
    }

    // 添加 USDC 存款 modifier
    modifier withUSDCDeposit(uint256 amount) {
        vm.startPrank(USER);

        // 给用户铸造 USDC
        deal(address(usdc), USER, amount);

        // 授权并存款
        IERC20(usdc).approve(address(engine), amount);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            amount,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );
        _;
    }

    function test_WithdrawWBTC() public withWBTCDeposit {
        uint256 beforeWbtcBalance = INITIAL_WBTC_BALANCE;
        // 获取借贷金额
        (uint256 totalWbtc, , uint256 totalBorrows, ) = engine.getUserTotals(
            USER
        );
        assertGt(totalBorrows, 0, "Should have borrowed USDC");

        // 验证 WBTC 余额
        assertEq(
            IERC20(wbtc).balanceOf(USER),
            beforeWbtcBalance - totalWbtc,
            "Incorrect WBTC balance change"
        );

        // 提款
        engine.withdraw(StrategyEngine.TokenType.WBTC, USER, totalBorrows);

        // 验证状态更新
        (uint256 newTotalWbtc, , uint256 newTotalBorrows, ) = engine
            .getUserTotals(USER);
        assertEq(newTotalWbtc, 0, "WBTC balance should be zero");
        assertEq(newTotalBorrows, 0, "Borrow amount should be zero");

        // 验证健康因子
        (, , , , , uint256 healthFactor) = engine.getUserAccountData(USER);
        assertGt(
            healthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Health factor should be greater than threshold after full repayment"
        );
    }

    function test_WithdrawUSDC() public withUSDCDeposit(1000e6) {
        // 验证存款
        (, uint256 totalUsdc, , ) = engine.getUserTotals(USER);
        assertEq(totalUsdc, 1000e6, "Incorrect USDC deposit amount");

        engine.withdraw(StrategyEngine.TokenType.USDC, USER, totalUsdc);

        // 验证状态更新
        (, uint256 newTotalUsdc, , ) = engine.getUserTotals(USER);
        assertEq(newTotalUsdc, 0, "USDC balance should be zero");
    }

    function test_WithdrawWithProfit() public withUSDCDeposit(1000e6) {
        uint256 profit = 100e6; // 100 USDC profit
        uint256 totalAmount = 1000e6 + profit;

        // 模拟利润（直接转入合约）
        deal(address(usdc), address(engine), totalAmount);

        // 提取全部金额（包含利润）
        engine.withdraw(StrategyEngine.TokenType.USDC, USER, totalAmount);

        // 验证平台费用
        uint256 platformFee = (profit * 1000) / 10000; // 10% of profit
        uint256 userProfit = profit - platformFee;

        // 验证 vault 余额
        assertEq(
            IERC20(usdc).balanceOf(address(engine.vault())),
            platformFee,
            "Incorrect platform fee in vault"
        );

        // 验证用户获得的奖励代币
        assertEq(
            engine.cpToken().balanceOf(USER),
            userProfit,
            "Incorrect reward token amount"
        );
    }

    function testFail_WithdrawInvalidAmount() public {
        vm.startPrank(USER);

        // 尝试提取未存入的金额
        engine.withdraw(StrategyEngine.TokenType.USDC, USER, 1000e6);

        vm.stopPrank();
    }

    function testFail_WithdrawWBTCWithHighBorrow() public withWBTCDeposit {
        // 验证存款后的健康因子
        (, , , , , uint256 initialHealthFactor) = engine.getUserAccountData(
            USER
        );
        assertLt(
            initialHealthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Initial health factor should be less than threshold"
        );

        uint256 engineBalance = IERC20(usdc).balanceOf(address(engine));

        // 尝试提取小于借贷金额的 USDC
        uint256 invalidWithdrawAmount = engineBalance +
            (engineBalance * 10) /
            100; // 减少 100 USDC
        engine.withdraw(
            StrategyEngine.TokenType.WBTC,
            USER,
            invalidWithdrawAmount
        );
    }

    function test_WithdrawWithUnhealthyFactor() public withWBTCDeposit {
        // 获取借贷金额
        (, , uint256 totalBorrows, ) = engine.getUserTotals(USER);
        uint256 profit = totalBorrows / 2; // 50% 的借贷金额作为获利
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + profit
        );

        // 使用低于借款的还款金额，这样还款后健康度仍低于标准值
        uint256 withdrawAmount = totalBorrows - (totalBorrows * 50) / 100;

        // 验证存款后的健康因子
        (, , , , , uint256 initialHealthFactor) = engine.getUserAccountData(
            USER
        );
        assertLt(
            initialHealthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Initial health factor should be less than threshold"
        );

        // 尝试提款
        engine.withdraw(StrategyEngine.TokenType.WBTC, USER, withdrawAmount);

        // 验证部分还款后的健康因子
        (, , , , , uint256 finalHealthFactor) = engine.getUserAccountData(USER);
        assertLt(
            finalHealthFactor,
            HEALTH_FACTOR_THRESHOLD,
            "Health factor should still be less than threshold after partial repayment"
        );

        // 验证只更新了借贷金额
        (, , uint256 newTotalBorrows, ) = engine.getUserTotals(USER);
        assertGt(newTotalBorrows, 0, "Borrow amount should not be zero");
    }

    function test_RepayAmountCalculation() public withWBTCDeposit {
        // 获取用户位置和借贷金额
        address userPosition = engine.userToPosition(USER);
        (, , uint256 totalBorrows, ) = engine.getUserTotals(USER);

        // 获取预期还款金额
        uint256 expectedRepayAmount = engine.calculateRepayAmount(
            address(usdc),
            userPosition
        );

        // 模拟 USDC 余额
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + totalBorrows
        );

        // 执行还款
        (, uint256 actualRepayAmount) = engine.withdraw(
            StrategyEngine.TokenType.WBTC,
            USER,
            totalBorrows
        );

        // 验证实际还款金额等于计算的应还款金额
        assertEq(
            expectedRepayAmount,
            actualRepayAmount,
            "Actual repay amount should equal calculated repay amount"
        );
    }

    function test_PartialRepayAmountCalculation() public withWBTCDeposit {
        // 获取用户位置和借贷金额
        address userPosition = engine.userToPosition(USER);
        (, , uint256 totalBorrows, ) = engine.getUserTotals(USER);

        // 验证部分还款
        uint256 partialAmount = totalBorrows / 2;
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + partialAmount
        );

        // 获取部分还款前的应还金额
        uint256 expectedPartialRepayAmount = engine.calculateRepayAmount(
            address(usdc),
            userPosition
        );

        // 执行部分还款
        engine.withdraw(StrategyEngine.TokenType.WBTC, USER, partialAmount);

        // 验证部分还款后的剩余应还金额
        uint256 remainingRepayAmount = engine.calculateRepayAmount(
            address(usdc),
            userPosition
        );
        assertEq(
            remainingRepayAmount,
            expectedPartialRepayAmount - partialAmount,
            "Remaining repay amount incorrect after partial repayment"
        );
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

        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        (v, r, s) = vm.sign(privateKey, digest);
    }
}
