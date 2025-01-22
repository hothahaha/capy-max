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
import {ITokenMessenger} from "./cctp/interface/ITokenMessenger.sol";
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
    uint8 private constant DESTINATION_DOMAIN = 5;

    // Token and protocol contracts
    IERC20 public wbtc;
    IERC20 public usdc;
    IAavePool public aavePool;
    IAaveOracle public aaveOracle;
    CpToken public cpToken;

    // 添加代币类型枚举
    enum TokenType {
        WBTC,
        USDC
    }

    // 修改存款记录结构体，添加代币类型
    struct DepositRecord {
        TokenType tokenType;
        uint256 amount;
        uint256 timestamp;
        uint256 borrowAmount;
    }

    // 修改 UserInfo 结构体
    struct UserInfo {
        uint256 totalWbtcAmount; // WBTC 总存款量
        uint256 totalUsdcAmount; // USDC 总存款量
        uint256 totalBorrowAmount; // 总借款量
        uint256 lastDepositTime;
        DepositRecord[] deposits; // 存款记录数组
    }

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

    // Add CCTP contract
    ITokenMessenger public cctp;

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
        address _cctp,
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
        cctp = ITokenMessenger(_cctp);
        solanaAccount = _solanaAccount;
    }

    /// @notice 实现 UUPS 升级功能
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {
        // 可以添加额外的升级条件
    }

    /// @notice 修改后的存款函数
    function deposit(
        TokenType tokenType,
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable nonReentrant {
        if (amount == 0) revert StrategyEngine__InvalidAmount();

        if (tokenType == TokenType.WBTC) {
            _handleWbtcDeposit(
                amount,
                onBehalfOf,
                referralCode,
                deadline,
                v,
                r,
                s
            );
        } else {
            _handleUsdcDeposit(amount);
        }
    }

    /// @dev 处理 WBTC 存款
    function _handleWbtcDeposit(
        uint256 amount,
        address onBehalfOf,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // 使用 permit 授权
        IERC20Permit(address(wbtc)).permit(
            msg.sender,
            address(this),
            amount,
            deadline,
            v,
            r,
            s
        );

        // 转移 WBTC
        wbtc.safeTransferFrom(msg.sender, address(this), amount);

        // Aave 供应
        wbtc.approve(address(aavePool), amount);
        aavePool.supply(address(wbtc), amount, onBehalfOf, referralCode);

        // 铸造 cpBTC
        cpToken.mint(msg.sender, amount);

        // 计算并借出 USDC
        uint256 borrowAmount = _calculateBorrowAmount(onBehalfOf);
        aavePool.borrow(address(usdc), borrowAmount, 2, 0, onBehalfOf);

        // CCTP 跨链传输
        usdc.approve(address(cctp), borrowAmount);
        cctp.depositForBurn(
            borrowAmount,
            DESTINATION_DOMAIN,
            solanaAccount,
            address(usdc)
        );

        // 更新用户信息
        _updateUserInfo(msg.sender, TokenType.WBTC, amount, borrowAmount);

        emit Deposited(msg.sender, amount);
    }

    /// @dev 处理 USDC 存款
    function _handleUsdcDeposit(uint256 amount) internal {
        // 转移 USDC
        usdc.safeTransferFrom(msg.sender, address(this), amount);

        // 更新用户信息
        _updateUserInfo(msg.sender, TokenType.USDC, amount, 0);

        emit Deposited(msg.sender, amount);
    }

    /// @dev 更新用户信息
    function _updateUserInfo(
        address user,
        TokenType tokenType,
        uint256 depositAmount,
        uint256 borrowAmount
    ) internal {
        UserInfo storage info = userInfo[user];

        // 创建新的存款记录
        DepositRecord memory newDeposit = DepositRecord({
            tokenType: tokenType,
            amount: depositAmount,
            timestamp: block.timestamp,
            borrowAmount: borrowAmount
        });

        // 添加存款记录
        info.deposits.push(newDeposit);

        // 根据代币类型更新总额
        if (tokenType == TokenType.WBTC) {
            info.totalWbtcAmount += depositAmount;
        } else {
            info.totalUsdcAmount += depositAmount;
        }

        info.totalBorrowAmount += borrowAmount;
        info.lastDepositTime = block.timestamp;
    }

    function withdraw(uint256 amount) external nonReentrant {
        // TODO
    }

    function _calculateBorrowAmount(
        address user
    ) internal view returns (uint256) {
        (
            uint256 totalCollateralBase,
            ,
            uint256 availableBorrowsBase,
            ,
            uint256 currentLt,

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

    // 添加获取用户存款记录的函数
    function getUserDepositRecords(
        address user
    ) external view returns (DepositRecord[] memory) {
        return userInfo[user].deposits;
    }

    // 修改查询函数以支持不同代币
    function getUserTotals(
        address user
    )
        external
        view
        returns (
            uint256 totalWbtc,
            uint256 totalUsdc,
            uint256 totalBorrows,
            uint256 lastDepositTime
        )
    {
        UserInfo storage info = userInfo[user];
        return (
            info.totalWbtcAmount,
            info.totalUsdcAmount,
            info.totalBorrowAmount,
            info.lastDepositTime
        );
    }
}
