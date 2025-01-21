// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console2} from "forge-std/console2.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import {AaveV3Arbitrum, AaveV3ArbitrumAssets} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

import {IAavePool} from "./aave/interface/IAavePool.sol";
import {IAaveOracle} from "./aave/interface/IAaveOracle.sol";
import {IVariableDebtToken} from "./aave/interface/IVariableDebtToken.sol";
import {IWormholeCCTP, TransferParameters} from "./wormhole/interface/IWormholeCCTP.sol";
import {CpToken} from "./tokens/CpToken.sol";

/// @title StrategyEngine
/// @notice Manages yield generation through AAVE and HyperLiquid
contract StrategyEngine is
    Initializable,
    UUPSUpgradeable,
    OwnableUpgradeable,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    // Constants
    uint256 private constant LTV_BELOW = 700;
    uint256 private constant MIN_STAKE_TIME = 5 days;

    // Token and protocol contracts
    IERC20 public wbtc;
    IERC20 public usdc;
    IAavePool public aavePool;
    IAaveOracle public aaveOracle;
    CpToken public cpToken;

    // User information storage
    struct UserInfo {
        uint256 depositAmount;
        uint256 depositTime;
        uint256 borrowedAmount;
    }

    // Active users list for efficient iteration
    address[] public activeUsers;
    mapping(address => uint256) private userIndex; // user address => index + 1 in activeUsers
    mapping(address => UserInfo) public userInfo;

    // Events
    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount, uint256 rewards);
    event EmergencyAction(address indexed user, string action);

    // Errors
    error StrategyEngine__InvalidAmount();
    error StrategyEngine__NoDeposit();
    error StrategyEngine__StakeTimeNotMet();
    error StrategyEngine__TransferFailed();
    error StrategyEngine__DeadlineExpired();
    error StrategyEngine__NoCollateral();
    error StrategyEngine__HealthFactorTooLow();
    error StrategyEngine__NoAvailableBorrows();
    error StrategyEngine__InsufficientExecutionFee();

    // Add Wormhole CCTP contract
    IWormholeCCTP public wormholeCCTP;

    // Add Solana account storage
    bytes32 public solanaAccount;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address _wbtc,
        address _usdc,
        address _cpToken,
        address _wormholeCCTP,
        bytes32 _solanaAccount
    ) public initializer {
        __Ownable_init(msg.sender);
        __ReentrancyGuard_init();
        __UUPSUpgradeable_init();

        wbtc = IERC20(_wbtc);
        usdc = IERC20(_usdc);
        aavePool = IAavePool(address(AaveV3Arbitrum.POOL));
        aaveOracle = IAaveOracle(address(AaveV3Arbitrum.ORACLE));
        cpToken = CpToken(_cpToken);
        wormholeCCTP = IWormholeCCTP(_wormholeCCTP);
        solanaAccount = _solanaAccount;
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    /// @notice Deposit WBTC with permit signature
    /// @dev Requires ETH value for GMX execution fee
    function deposit(
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable nonReentrant {
        if (amount == 0) revert StrategyEngine__InvalidAmount();

        // 1. First use permit to approve StrategyEngine
        IERC20Permit(address(wbtc)).permit(
            msg.sender,
            address(this),
            amount,
            deadline,
            v,
            r,
            s
        );

        // 2. Then use regular supply instead of supplyWithPermit
        wbtc.safeTransferFrom(msg.sender, address(this), amount);

        wbtc.approve(address(aavePool), amount);
        aavePool.supply(address(wbtc), amount, onBehalfOf, referralCode);

        // Mint cpBTC to user
        cpToken.mint(msg.sender, amount);

        // 计算用户可以借出的 USDC 数量
        uint256 borrowAmount = _calculateBorrowAmount(onBehalfOf);

        // 从 Aave 借出 USDC
        aavePool.borrow(
            address(usdc),
            borrowAmount,
            2, // 变动利率模式
            0, // 推荐码
            onBehalfOf // credit delegator
        );

        // Approve USDC for Wormhole CCTP
        usdc.approve(address(wormholeCCTP), borrowAmount);

        // Prepare transfer parameters for Wormhole CCTP
        TransferParameters memory transferParams = TransferParameters({
            token: address(usdc),
            amount: borrowAmount,
            targetChain: 1,
            mintRecipient: solanaAccount
        });

        // Transfer USDC cross-chain using Wormhole CCTP
        // 将借出的USDC转到Solana个人钱包
        wormholeCCTP.transferTokensWithPayload(
            transferParams,
            0, // batchId
            "" // Empty payload as we don't need additional data
        );

        // 更新用户信息
        _updateUserInfo(msg.sender, amount, borrowAmount);

        emit Deposited(msg.sender, amount);
    }

    function withdraw(uint256 amount) external nonReentrant {
        UserInfo storage user = userInfo[msg.sender];
        if (user.depositAmount < amount) revert StrategyEngine__InvalidAmount();

        // Burn cpBTC
        cpToken.burn(msg.sender, amount);

        // Withdraw logic will be implemented here
        // ...

        emit Withdrawn(msg.sender, amount, 0);
    }

    /// @dev 更新用户信息并维护活跃用户列表
    function _updateUserInfo(
        address user,
        uint256 depositAmount,
        uint256 borrowAmount
    ) internal {
        UserInfo storage info = userInfo[user];

        // 如果是新用户，添加到活跃用户列表
        if (userIndex[user] == 0) {
            activeUsers.push(user);
            userIndex[user] = activeUsers.length;
        }

        // 更新用户信息
        info.depositAmount = depositAmount;
        info.depositTime = block.timestamp;
        info.borrowedAmount = borrowAmount;
    }

    /// @notice 获取活跃用户数量
    function getActiveUsersCount() external view returns (uint256) {
        return activeUsers.length;
    }

    /// @notice 批量获取用户信息
    /// @param start 起始索引
    /// @param end 结束索引
    function batchGetUserInfo(
        uint256 start,
        uint256 end
    ) external view returns (address[] memory users, UserInfo[] memory infos) {
        if (end > activeUsers.length) {
            end = activeUsers.length;
        }
        if (start >= end) {
            return (new address[](0), new UserInfo[](0));
        }

        uint256 length = end - start;
        users = new address[](length);
        infos = new UserInfo[](length);

        for (uint256 i = 0; i < length; i++) {
            address user = activeUsers[start + i];
            users[i] = user;
            infos[i] = userInfo[user];
        }

        return (users, infos);
    }

    function _calculateBorrowAmount(
        address user
    ) internal view returns (uint256) {
        (
            uint256 totalCollateralBase,
            ,
            uint256 availableBorrowsBase,
            uint256 currentLt,
            ,

        ) = _getUserAccountData(user);

        // 检查用户是否有足够的抵押物
        if (totalCollateralBase == 0) revert StrategyEngine__NoCollateral();

        // 检查用户是否有足够的可借金额
        if (availableBorrowsBase == 0)
            revert StrategyEngine__NoAvailableBorrows();

        // LTV - 7%
        uint256 maxBorrowIn = (totalCollateralBase * (currentLt - LTV_BELOW)) /
            1e4;
        uint256 usdcPrice = aaveOracle.getAssetPrice(address(usdc));
        uint256 borrowAmount = (maxBorrowIn *
            10 ** IERC20Metadata(address(usdc)).decimals()) / usdcPrice;

        return borrowAmount;
    }

    function getUserAccountData(
        address user
    )
        public
        view
        returns (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        )
    {
        return _getUserAccountData(user);
    }

    function _getUserAccountData(
        address user
    )
        public
        view
        returns (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            uint256 availableBorrowsBase,
            uint256 currentLiquidationThreshold,
            uint256 ltv,
            uint256 healthFactor
        )
    {
        return aavePool.getUserAccountData(user);
    }
}
