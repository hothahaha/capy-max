// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

import {IAavePool} from "../src/aave/interface/IAavePool.sol";
import {IPoolDataProvider} from "../src/aave/interface/IAaveProtocolDataProvider.sol";
import {IVariableDebtToken} from "../src/aave/interface/IVariableDebtToken.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";

contract StrategyEngineTest is Test {
    IPoolDataProvider public aaveProtocolDataProvider;
    IAavePool public aavePool;
    StrategyEngine public engine;
    address public wbtc;
    address public usdc;
    address public USER;
    uint256 public USER_PRIVATE_KEY;
    uint256 public constant INITIAL_ETH_BALANCE = 10 ether;
    uint256 public constant INITIAL_WBTC_BALANCE = 1000e8;
    uint256 public constant GMX_EXECUTION_FEE = 0.011 ether;

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
        (wbtc, usdc, , , ) = config.activeNetworkConfig();

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

        _approveDelegation(usdc, USER, type(uint256).max);

        // 记录存款前的余额
        uint256 beforeWbtcBalance = IERC20(wbtc).balanceOf(USER);
        uint256 beforeCpTokenBalance = engine.cpToken().balanceOf(USER);

        // 执行存款
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            amount,
            USER,
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

        // 验证 cpToken 铸造
        assertEq(
            engine.cpToken().balanceOf(USER),
            beforeCpTokenBalance + amount,
            "Incorrect cpToken mint amount"
        );

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
            USER,
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
            USER,
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
            USER,
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
            USER,
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

    function test_WithdrawWBTC() public {
        uint256 depositAmount = 1e7;
        uint256 deadline = block.timestamp + 1 days;
        uint256 beforeWbtcBalance = IERC20(wbtc).balanceOf(USER);

        // 准备存款
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
        _approveDelegation(usdc, USER, type(uint256).max);

        // 先进行存款
        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            depositAmount,
            USER,
            0,
            deadline,
            v,
            r,
            s
        );

        // 获取借贷金额
        (, , uint256 totalBorrows, ) = engine.getUserTotals(USER);
        assertGt(totalBorrows, 0, "Should have borrowed USDC");

        // 验证 WBTC 余额
        assertEq(
            IERC20(wbtc).balanceOf(USER),
            beforeWbtcBalance - depositAmount,
            "Incorrect Before WBTC balance change"
        );

        // 模拟 USDC 获利（50% 的借贷金额）
        uint256 profit = totalBorrows / 2;
        uint256 withdrawAmount = totalBorrows + profit;
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + profit
        );

        // 执行提款
        engine.withdraw(StrategyEngine.TokenType.WBTC, USER, withdrawAmount);

        // 从 Aave 提取 WBTC 本金
        _withdrawFromAave(address(wbtc), depositAmount, USER);

        // 验证 WBTC 余额
        assertEq(
            IERC20(wbtc).balanceOf(USER),
            beforeWbtcBalance,
            "Incorrect After WBTC balance change"
        );

        // 验证状态更新
        (uint256 newTotalWbtc, , uint256 newTotalBorrows, ) = engine
            .getUserTotals(USER);
        assertEq(newTotalWbtc, 0, "WBTC balance should be zero");
        assertEq(newTotalBorrows, 0, "Borrow amount should be zero");

        vm.stopPrank();
    }

    function test_WithdrawUSDC() public {
        uint256 depositAmount = 1000e6; // 1000 USDC

        vm.startPrank(USER);

        // 给用户铸造 USDC
        deal(address(usdc), USER, depositAmount);

        // 授权并存入 USDC
        IERC20(usdc).approve(address(engine), depositAmount);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            depositAmount,
            USER,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );

        // 验证存款
        (, uint256 totalUsdc, , ) = engine.getUserTotals(USER);
        assertEq(totalUsdc, depositAmount, "Incorrect USDC deposit amount");

        // 执行提款
        engine.withdraw(StrategyEngine.TokenType.USDC, USER, depositAmount);

        // 验证提款后状态
        (, uint256 newTotalUsdc, , ) = engine.getUserTotals(USER);
        assertEq(newTotalUsdc, 0, "USDC balance should be zero");

        vm.stopPrank();
    }

    function test_WithdrawWithProfit() public {
        uint256 depositAmount = 1000e6; // 1000 USDC
        uint256 profit = 100e6; // 100 USDC profit
        uint256 totalAmount = depositAmount + profit;

        vm.startPrank(USER);

        // 给用户铸造 USDC
        deal(address(usdc), USER, depositAmount);

        // 存入 USDC
        IERC20(usdc).approve(address(engine), depositAmount);
        engine.deposit(
            StrategyEngine.TokenType.USDC,
            depositAmount,
            USER,
            0,
            0,
            0,
            bytes32(0),
            bytes32(0)
        );

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

        vm.stopPrank();
    }

    function testFail_WithdrawInvalidAmount() public {
        vm.startPrank(USER);

        // 尝试提取未存入的金额
        engine.withdraw(StrategyEngine.TokenType.USDC, USER, 1000e6);

        vm.stopPrank();
    }

    function testFail_WithdrawWBTCWithHighBorrow() public {
        uint256 depositAmount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        // 存款
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
        _approveDelegation(usdc, USER, type(uint256).max);

        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            depositAmount,
            USER,
            0,
            deadline,
            v,
            r,
            s
        );

        // 尝试提取小于借贷金额的 USDC
        uint256 invalidWithdrawAmount = depositAmount - 100e6; // 减少 100 USDC
        engine.withdraw(
            StrategyEngine.TokenType.WBTC,
            USER,
            invalidWithdrawAmount
        );

        vm.stopPrank();
    }

    function test_WithdrawWithUnhealthyFactor() public {
        uint256 depositAmount = 1e7;
        uint256 deadline = block.timestamp + 1 days;

        // 存款
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
        _approveDelegation(usdc, USER, type(uint256).max);

        engine.deposit{value: GMX_EXECUTION_FEE}(
            StrategyEngine.TokenType.WBTC,
            depositAmount,
            USER,
            0,
            deadline,
            v,
            r,
            s
        );

        // 获取借贷金额
        (, , uint256 totalBorrows, ) = engine.getUserTotals(USER);
        uint256 profit = totalBorrows / 2; // 50% 的借贷金额作为获利
        uint256 withdrawAmount = totalBorrows + profit;
        deal(
            address(usdc),
            address(engine),
            IERC20(usdc).balanceOf(address(engine)) + profit
        );

        // 模拟不健康的健康因子
        vm.mockCall(
            address(engine.aavePool()),
            abi.encodeWithSelector(IAavePool.getUserAccountData.selector, USER),
            abi.encode(
                1e18, // totalCollateralBase
                1e18, // totalDebtBase
                0, // availableBorrowsBase
                8000, // currentLiquidationThreshold
                7500, // ltv
                0.5e18 // healthFactor < 1
            )
        );

        // 尝试提款
        engine.withdraw(StrategyEngine.TokenType.WBTC, USER, withdrawAmount);

        // 验证只更新了借贷金额
        (, , uint256 newTotalBorrows, ) = engine.getUserTotals(USER);
        assertGt(newTotalBorrows, 0, "Borrow amount should not be zero");

        vm.stopPrank();
        vm.clearMockedCalls();
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

    /// @notice 授权用户可以偿还最大值的债务
    function _approveDelegation(
        address token,
        address user,
        uint256 amount
    ) internal {
        aaveProtocolDataProvider = IPoolDataProvider(
            address(AaveV3Arbitrum.AAVE_PROTOCOL_DATA_PROVIDER)
        );

        (, , address variableDebtTokenAddress) = aaveProtocolDataProvider
            .getReserveTokensAddresses(token);

        IVariableDebtToken(variableDebtTokenAddress).approveDelegation(
            address(engine),
            amount
        );

        uint256 borrowAllowance = IVariableDebtToken(variableDebtTokenAddress)
            .borrowAllowance(user, address(engine));
        assertEq(borrowAllowance, amount, "Incorrect borrow allowance");
    }

    /// @notice 从 Aave 提取用户的本金
    function _withdrawFromAave(
        address token,
        uint256 amount,
        address user
    ) internal {
        aavePool = IAavePool(engine.aavePool());
        aavePool.withdraw(token, amount, user);
    }
}
