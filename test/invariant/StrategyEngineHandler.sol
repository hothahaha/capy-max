// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {IAaveOracle} from "../../src/aave/interface/IAaveOracle.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";

contract StrategyEngineHandler is Test {
    StrategyEngine public engine;
    address public wbtc;
    address public usdc;
    address public aaveOracle;
    address public deployer;

    address[] public users;
    mapping(address => uint256) public userPrivateKeys;
    uint256 public lastVaultBalance;
    uint256 public totalProfit;

    uint256 public constant MAX_USERS = 20;

    constructor(
        address _engine,
        address _wbtc,
        address _usdc,
        address _aaveOracle,
        address _deployer
    ) {
        engine = StrategyEngine(_engine);
        wbtc = _wbtc;
        usdc = _usdc;
        aaveOracle = _aaveOracle;
        deployer = _deployer;

        // 初始化用户数组
        users = new address[](MAX_USERS);

        // 授权引擎使用代币
        IERC20(wbtc).approve(address(engine), type(uint256).max);
        IERC20(usdc).approve(address(engine), type(uint256).max);
    }

    // 创建新用户
    function createUser(uint256 seed) public {
        uint256 index = seed % MAX_USERS;
        if (users[index] == address(0)) {
            string memory userSeed = string(abi.encodePacked("user", seed));
            (address user, uint256 privateKey) = makeAddrAndKey(userSeed);
            users[index] = user;
            userPrivateKeys[user] = privateKey;

            // 给用户分配代币
            deal(wbtc, user, 10_000e8);
            deal(usdc, user, 10_000e6);

            // 授权引擎使用代币
            vm.startPrank(user);
            IERC20(wbtc).approve(address(engine), type(uint256).max);
            IERC20(usdc).approve(address(engine), type(uint256).max);
            vm.stopPrank();
        }
    }

    // 存入WBTC
    function depositWbtc(uint256 userSeed, uint256 amount) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        // 约束金额在合理范围内
        amount = bound(amount, 1, 1000e8);

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = IERC20Permit(wbtc).nonces(user);

        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            wbtc,
            user,
            address(engine),
            amount,
            nonce,
            deadline,
            userPrivateKeys[user]
        );

        vm.prank(user);
        try
            engine.deposit(
                StrategyEngine.TokenType.WBTC,
                amount,
                0, // referralCode
                deadline,
                v,
                r,
                s
            )
        {} catch {}
    }

    // 存入USDC
    function depositUsdc(uint256 userSeed, uint256 amount) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        // 约束金额在合理范围内，确保不超过用户余额
        uint256 userBalance = IERC20(usdc).balanceOf(user);
        uint256 maxAmount = userBalance < 1000e6 ? userBalance : 1000e6;
        amount = bound(amount, 1, maxAmount);

        vm.prank(user);
        try
            engine.deposit(
                StrategyEngine.TokenType.USDC,
                amount,
                0, // referralCode
                0, // deadline (不需要)
                0, // v (不需要)
                bytes32(0), // r (不需要)
                bytes32(0) // s (不需要)
            )
        {} catch {}
    }

    // 提取资金
    function withdraw(uint256 userSeed, uint256 tokenTypeSeed, uint256 amount) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        StrategyEngine.TokenType tokenType = tokenTypeSeed % 2 == 0
            ? StrategyEngine.TokenType.WBTC
            : StrategyEngine.TokenType.USDC;

        // 获取用户存款信息
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(user);

        // 确定可提取金额
        uint256 maxWithdraw;
        if (tokenType == StrategyEngine.TokenType.WBTC && totalWbtc > 0) {
            // 模拟利润返回
            uint256 profit = totalBorrows / 10; // 10% 利润
            deal(usdc, address(engine), totalBorrows + profit);
            maxWithdraw = totalBorrows + profit;
        } else if (tokenType == StrategyEngine.TokenType.USDC && totalUsdc > 0) {
            // 模拟利润返回
            uint256 profit = totalUsdc / 10; // 10% 利润
            deal(usdc, address(engine), totalUsdc + profit);
            maxWithdraw = totalUsdc + profit;
        } else {
            return; // 没有可提取的资金
        }

        // 约束提取金额，确保不超过最大可提取金额
        if (maxWithdraw == 0) return;
        amount = bound(amount, 1, maxWithdraw);

        vm.prank(user);
        try engine.withdraw(tokenType, user, amount) returns (
            uint256 userProfit,
            uint256 /* repayAaveAmount */
        ) {
            // 记录总利润
            totalProfit += userProfit;
        } catch {}
    }

    // 更新借款能力
    function updateBorrowCapacity(uint256 userSeed, uint256 priceFactor) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        // 约束价格因子在合理范围内 (50% - 200%)
        priceFactor = bound(priceFactor, 50, 200);

        // 模拟BTC价格变化
        uint256 originalPrice = IAaveOracle(aaveOracle).getAssetPrice(wbtc);
        uint256 newPrice = (originalPrice * priceFactor) / 100;

        vm.mockCall(
            aaveOracle,
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, wbtc),
            abi.encode(newPrice)
        );

        try engine.updateBorrowCapacity(user) {} catch {}

        // 恢复原始价格
        vm.mockCall(
            aaveOracle,
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, wbtc),
            abi.encode(originalPrice)
        );
    }

    // 执行健康检查
    function performHealthCheck() public {
        // 前进时间1小时以确保可以执行健康检查
        vm.warp(block.timestamp + 1 hours);

        try engine.performUpkeep("") {} catch {}
    }

    // 更新平台费用
    function updatePlatformFee(uint256 newFee) public {
        // 约束费用在有效范围内 (0-100%)
        newFee = bound(newFee, 0, 10000);

        vm.prank(deployer);
        try engine.updatePlatformFee(newFee) {} catch {}
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

    function getUsers() public view returns (address[] memory) {
        return users;
    }

    function getUserCount() public view returns (uint256) {
        return users.length;
    }

    function getUserPrivateKey(address user) public view returns (uint256) {
        return userPrivateKeys[user];
    }

    function getLastVaultBalance() public view returns (uint256) {
        return lastVaultBalance;
    }

    function updateLastVaultBalance() public {
        lastVaultBalance = IERC20(usdc).balanceOf(address(engine.vault()));
    }

    function getTotalProfit() public view returns (uint256) {
        return totalProfit;
    }

    // 辅助函数：打印用户信息，用于调试
    function printUserInfo(address user) public view {
        (
            uint256 totalWbtc,
            uint256 totalUsdc,
            uint256 totalBorrows,
            uint256 lastDepositTime
        ) = engine.getUserTotals(user);
        StrategyEngine.DepositRecord[] memory records = engine.getUserDepositRecords(user);

        console.log("User:", user);
        console.log("Total WBTC:", totalWbtc);
        console.log("Total USDC:", totalUsdc);
        console.log("Total Borrows:", totalBorrows);
        console.log("Last Deposit Time:", lastDepositTime);
        console.log("Deposit Records Count:", records.length);

        for (uint256 i = 0; i < records.length; i++) {
            console.log("Record", i);
            console.log("  Token Type:", uint256(records[i].tokenType));
            console.log("  Amount:", records[i].amount);
            console.log("  Borrow Amount:", records[i].borrowAmount);
            console.log("  Timestamp:", records[i].timestamp);
        }
    }
}
