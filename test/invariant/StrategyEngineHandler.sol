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

        // Initialize users array
        users = new address[](MAX_USERS);

        // Authorize engine to use tokens
        IERC20(wbtc).approve(address(engine), type(uint256).max);
        IERC20(usdc).approve(address(engine), type(uint256).max);
    }

    // Create new user
    function createUser(uint256 seed) public {
        uint256 index = seed % MAX_USERS;
        if (users[index] == address(0)) {
            string memory userSeed = string(abi.encodePacked("user", seed));
            (address user, uint256 privateKey) = makeAddrAndKey(userSeed);
            users[index] = user;
            userPrivateKeys[user] = privateKey;

            // Assign tokens to user
            deal(wbtc, user, 10_000e8);
            deal(usdc, user, 10_000e6);

            // Authorize engine to use tokens
            vm.startPrank(user);
            IERC20(wbtc).approve(address(engine), type(uint256).max);
            IERC20(usdc).approve(address(engine), type(uint256).max);
            vm.stopPrank();
        }
    }

    // Deposit WBTC
    function depositWbtc(uint256 userSeed, uint256 amount) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        // Constraint amount in a reasonable range
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

    // Deposit USDC
    function depositUsdc(uint256 userSeed, uint256 amount) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        // Constraint amount in a reasonable range, ensuring it does not exceed user balance
        uint256 userBalance = IERC20(usdc).balanceOf(user);
        uint256 maxAmount = userBalance < 1000e6 ? userBalance : 1000e6;
        amount = bound(amount, 1, maxAmount);

        vm.prank(user);
        try
            engine.deposit(
                StrategyEngine.TokenType.USDC,
                amount,
                0, // referralCode
                0, // deadline (not needed)
                0, // v (not needed)
                bytes32(0), // r (not needed)
                bytes32(0) // s (not needed)
            )
        {} catch {}
    }

    // Withdraw funds
    function withdraw(uint256 userSeed, uint256 tokenTypeSeed, uint256 amount) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        StrategyEngine.TokenType tokenType = tokenTypeSeed % 2 == 0
            ? StrategyEngine.TokenType.WBTC
            : StrategyEngine.TokenType.USDC;

        // Get user deposit information
        (uint256 totalWbtc, uint256 totalUsdc, uint256 totalBorrows, ) = engine.getUserTotals(user);

        // Determine the amount that can be withdrawn
        uint256 maxWithdraw;
        if (tokenType == StrategyEngine.TokenType.WBTC && totalWbtc > 0) {
            // Simulate profit return
            uint256 profit = totalBorrows / 10; // 10% profit
            deal(usdc, address(engine), totalBorrows + profit);
            maxWithdraw = totalBorrows + profit;
        } else if (tokenType == StrategyEngine.TokenType.USDC && totalUsdc > 0) {
            // Simulate profit return
            uint256 profit = totalUsdc / 10; // 10% profit
            deal(usdc, address(engine), totalUsdc + profit);
            maxWithdraw = totalUsdc + profit;
        } else {
            return; // No funds to withdraw
        }

        // Constraint withdrawal amount, ensuring it does not exceed the maximum withdrawable amount
        if (maxWithdraw == 0) return;
        amount = bound(amount, 1, maxWithdraw);

        vm.prank(user);
        try engine.withdraw(tokenType, user, amount) returns (
            uint256 userProfit,
            uint256 /* repayAaveAmount */
        ) {
            // Record total profit
            totalProfit += userProfit;
        } catch {}
    }

    // Update borrow capacity
    function updateBorrowCapacity(uint256 userSeed, uint256 priceFactor) public {
        uint256 index = userSeed % MAX_USERS;
        address user = users[index];
        if (user == address(0)) return;

        // Constraint price factor in a reasonable range (50% - 200%)
        priceFactor = bound(priceFactor, 50, 200);

        // Simulate BTC price change
        uint256 originalPrice = IAaveOracle(aaveOracle).getAssetPrice(wbtc);
        uint256 newPrice = (originalPrice * priceFactor) / 100;

        vm.mockCall(
            aaveOracle,
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, wbtc),
            abi.encode(newPrice)
        );

        try engine.updateBorrowCapacity(user) {} catch {}

        // Restore original price
        vm.mockCall(
            aaveOracle,
            abi.encodeWithSelector(IAaveOracle.getAssetPrice.selector, wbtc),
            abi.encode(originalPrice)
        );
    }

    // Perform health check
    function performHealthCheck() public {
        // Advance time 1 hour to ensure health check can be performed
        vm.warp(block.timestamp + 1 hours);

        try engine.performUpkeep("") {} catch {}
    }

    // Update platform fee
    function updatePlatformFee(uint256 newFee) public {
        // Constraint fee in a valid range (0-100%)
        newFee = bound(newFee, 0, 10000);

        vm.prank(deployer);
        try engine.updatePlatformFee(newFee) {} catch {}
    }

    // Helper function: Generate valid signature
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

    // Helper function: Print user information, for debugging
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
