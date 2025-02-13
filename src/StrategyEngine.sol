// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console2} from "forge-std/console2.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeableBase} from "./upgradeable/UUPSUpgradeableBase.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";

import {IAavePool} from "./aave/interface/IAavePool.sol";
import {IAaveOracle} from "./aave/interface/IAaveOracle.sol";
import {IPoolDataProvider} from "./aave/interface/IAaveProtocolDataProvider.sol";
import {ITokenMessenger} from "./cctp/interface/ITokenMessenger.sol";
import {CpToken} from "./tokens/CpToken.sol";
import {Vault} from "./vault/Vault.sol";
import {UserPosition} from "./UserPosition.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {SignerManager} from "./access/SignerManager.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IStrategyEngine} from "./interfaces/IStrategyEngine.sol";

/// @title StrategyEngine
/// @notice Manages yield generation through AAVE and HyperLiquid
contract StrategyEngine is
    IStrategyEngine,
    Initializable,
    UUPSUpgradeableBase,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;

    // Constants
    uint256 private constant LTV_BELOW = 700;
    uint256 private constant BASIS_POINTS = 10000; // 100%

    uint256 private platformFeePercentage;
    bytes32 private solanaAddress;

    // Token and protocol contracts
    IERC20 public wbtc;
    IERC20 public usdc;
    IAavePool public aavePool;
    IAaveOracle public aaveOracle;
    IPoolDataProvider public aaveProtocolDataProvider;
    ITokenMessenger public tokenMessenger;
    CpToken public cpToken;
    SignerManager public signerManager;

    // 添加代币类型枚举
    enum TokenType {
        WBTC,
        USDC
    }

    // 修改存款记录结构体，添加代币类型
    struct DepositRecord {
        bytes32 depositId;
        TokenType tokenType;
        uint256 amount;
        uint256 timestamp;
        uint256 borrowAmount;
    }

    // 修改 UserInfo 结构体
    struct UserInfo {
        uint256 totalWbtcDeposited;
        uint256 totalUsdcDeposited;
        uint256 totalBorrowAmount;
        uint256 lastDepositTime;
        DepositRecord[] deposits;
    }

    mapping(address => UserInfo) public userInfo;

    // Events
    event Deposited(
        bytes32 indexed depositId,
        address indexed user,
        TokenType tokenType,
        uint256 amount,
        uint256 borrowAmount
    );
    event Withdrawn(address indexed user, uint256 amount, uint256 rewards);
    event EmergencyAction(address indexed user, string action);
    event PlatformFeeUpdated(uint256 oldFee, uint256 newFee);

    // Errors
    error StrategyEngine__InvalidAmount();
    error StrategyEngine__WithdrawAmountTooHigh();
    error StrategyEngine__NoDeposit();
    error StrategyEngine__StakeTimeNotMet();
    error StrategyEngine__TransferFailed();
    error StrategyEngine__DeadlineExpired();
    error StrategyEngine__NoCollateral();
    error StrategyEngine__HealthFactorTooLow();
    error StrategyEngine__NoAvailableBorrows();
    error StrategyEngine__InsufficientExecutionFee();
    error StrategyEngine__PositionAlreadyExists();
    error StrategyEngine__PositionNotFound();
    error StrategyEngine__InvalidFeePercentage();
    error StrategyEngine__Unauthorized();
    error StrategyEngine__InvalidImplementation();
    // 添加状态变量
    Vault public vault;

    // 添加用户位置映射
    mapping(address => address) public userToPosition;
    mapping(address => address) public positionToUser;

    modifier onlySigner() {
        if (!signerManager.isSigner(msg.sender)) {
            revert StrategyEngine__Unauthorized();
        }
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(EngineInitParams memory params) public initializer {
        __UUPSUpgradeableBase_init(msg.sender);
        __ReentrancyGuard_init();

        // 设置初始平台费用
        platformFeePercentage = 1000;
        solanaAddress = params.solanaAddress;
        wbtc = IERC20(params.wbtc);
        usdc = IERC20(params.usdc);
        aavePool = IAavePool(params.aavePool);
        aaveOracle = IAaveOracle(params.aaveOracle);
        aaveProtocolDataProvider = IPoolDataProvider(
            params.aaveProtocolDataProvider
        );
        tokenMessenger = ITokenMessenger(params.tokenMessenger);
        cpToken = CpToken(params.cpToken);
        vault = Vault(params.vault);
        signerManager = SignerManager(params.signerManager);
    }

    function generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return _generateDepositId(user, tokenType, amount, timestamp);
    }

    /// @dev 生成唯一的 depositId
    function _generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, tokenType, amount, timestamp));
    }

    /// @notice 存款函数
    /// @dev 根据存入的代币类型，如果是 WBTC，则需要授权，并存入 Aave
    /// @dev 如果是 USDC，则直接存入 当前合约
    function deposit(
        TokenType tokenType,
        uint256 amount,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable nonReentrant {
        if (amount == 0) revert StrategyEngine__InvalidAmount();

        if (tokenType == TokenType.WBTC) {
            _handleWbtcDeposit(amount, referralCode, deadline, v, r, s);
        } else {
            _handleUsdcDeposit(amount);
        }
    }

    /// @dev 处理 WBTC 存款
    function _handleWbtcDeposit(
        uint256 amount,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // 获取或创建用户位置
        address userPosition = userToPosition[msg.sender];
        if (userPosition == address(0)) {
            userPosition = _createUserPosition(msg.sender);
        }

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

        // 转移 WBTC 到合约
        wbtc.safeTransferFrom(msg.sender, address(this), amount);

        // 转移到用户位置并存入 Aave
        wbtc.safeTransfer(userPosition, amount);
        UserPosition(payable(userPosition)).executeAaveDeposit(
            address(aavePool),
            address(wbtc),
            amount,
            referralCode
        );

        // 计算并借出 USDC
        uint256 borrowAmount = _calculateBorrowAmount(userPosition);
        UserPosition(payable(userPosition)).executeBorrow(
            address(aavePool),
            address(usdc),
            borrowAmount,
            2, // Variable rate
            0 // referralCode
        );
        usdc.safeTransferFrom(userPosition, address(this), borrowAmount);

        // 更新用户信息
        _updateUserInfo(msg.sender, TokenType.WBTC, amount, borrowAmount);

        bytes32 depositId = _generateDepositId(
            msg.sender,
            TokenType.WBTC,
            amount,
            block.timestamp
        );

        emit Deposited(
            depositId,
            msg.sender,
            TokenType.WBTC,
            amount,
            borrowAmount
        );

        bridge(borrowAmount);
    }

    /// @dev 处理 USDC 存款
    function _handleUsdcDeposit(uint256 amount) internal {
        // 转移 USDC
        usdc.safeTransferFrom(msg.sender, address(this), amount);

        // 更新用户信息
        _updateUserInfo(msg.sender, TokenType.USDC, amount, 0);

        bytes32 depositId = _generateDepositId(
            msg.sender,
            TokenType.USDC,
            amount,
            block.timestamp
        );

        emit Deposited(depositId, msg.sender, TokenType.USDC, amount, 0);

        bridge(amount);
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
            depositId: _generateDepositId(
                user,
                tokenType,
                depositAmount,
                block.timestamp
            ),
            tokenType: tokenType,
            amount: depositAmount,
            timestamp: block.timestamp,
            borrowAmount: borrowAmount
        });

        // 添加存款记录
        info.deposits.push(newDeposit);

        // 根据代币类型更新总额
        if (tokenType == TokenType.WBTC) {
            info.totalWbtcDeposited += depositAmount;
        } else {
            info.totalUsdcDeposited += depositAmount;
        }

        info.totalBorrowAmount += borrowAmount;
        info.lastDepositTime = block.timestamp;
    }

    /// @notice 提款函数
    /// @dev 根据存入的代币类型，如果是 WBTC，则需要偿还 Aave 借款，检查健康度，并取回抵押品
    /// @dev 如果是 USDC，则直接提款
    /// @dev 计算利润，计算平台费用，将平台费用存入 vault，将用户利润转出
    /// @dev 返回用户利润和实际偿还的 Aave 借款金额
    function withdraw(
        TokenType tokenType,
        address user,
        uint256 amount
    )
        external
        nonReentrant
        returns (uint256 userProfit, uint256 repayAaveAmount)
    {
        if (amount == 0) revert StrategyEngine__InvalidAmount();

        uint256 engineBalance = usdc.balanceOf(address(this));
        if (engineBalance < amount)
            revert StrategyEngine__WithdrawAmountTooHigh();

        UserInfo storage info = userInfo[user];
        uint256 profit;
        uint256 withdrawUSDCAmount;

        if (tokenType == TokenType.WBTC) {
            address userPosition = userToPosition[user];
            if (userPosition == address(0))
                revert StrategyEngine__PositionNotFound();

            usdc.safeTransfer(userPosition, amount);
            // 偿还 Aave 借款
            uint256 repayAmount = _calculateRepayAmount(
                address(usdc),
                userPosition
            );

            repayAaveAmount = UserPosition(payable(userPosition)).executeRepay(
                address(aavePool),
                address(usdc),
                amount,
                2 // Variable rate
            );

            if (amount >= repayAmount) {
                // 计算利润
                profit = amount - repayAmount;

                // 转移剩余 USDC 到 engine
                usdc.safeTransferFrom(userPosition, address(this), profit);

                uint256 wbtcAmount = info.totalWbtcDeposited;

                // 取回抵押品
                UserPosition(payable(userPosition)).executeAaveWithdraw(
                    address(aavePool),
                    address(wbtc),
                    wbtcAmount,
                    user
                );

                // 更新用户信息
                info.totalWbtcDeposited = 0;
                info.totalBorrowAmount = 0;
            } else {
                info.totalBorrowAmount -= amount;
                return (0, repayAaveAmount);
            }
        } else {
            // 计算利润
            profit = amount - info.totalUsdcDeposited;

            withdrawUSDCAmount = info.totalUsdcDeposited;

            // 更新用户信息
            info.totalUsdcDeposited = 0;
        }

        if (profit > 0) {
            // 计算平台费用
            uint256 platformFee = (profit * platformFeePercentage) /
                BASIS_POINTS;
            userProfit = profit - platformFee;

            // 将平台费用存入 vault
            if (platformFee > 0) {
                usdc.safeTransfer(address(vault), platformFee);
            }

            withdrawUSDCAmount += userProfit;

            // 转出用户利润
            usdc.safeTransfer(msg.sender, withdrawUSDCAmount);

            // 铸造奖励代币
            cpToken.mint(msg.sender, userProfit);

            return (userProfit, repayAaveAmount);
        }

        emit Withdrawn(msg.sender, amount, profit);
    }

    function createUserPosition() external {
        _createUserPosition(msg.sender);
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
        address userPosition = userToPosition[user];
        return _getUserAccountData(userPosition);
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

    function calculateRepayAmount(
        address asset,
        address user
    ) public view returns (uint256) {
        return _calculateRepayAmount(asset, user);
    }

    function _calculateRepayAmount(
        address asset,
        address user
    ) internal view returns (uint256) {
        (, , uint256 currentVariableDebt, , , , , , ) = aaveProtocolDataProvider
            .getUserReserveData(asset, user);
        return currentVariableDebt;
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
            info.totalWbtcDeposited,
            info.totalUsdcDeposited,
            info.totalBorrowAmount,
            info.lastDepositTime
        );
    }

    function _createUserPosition(address user) internal returns (address) {
        if (userToPosition[user] != address(0))
            revert StrategyEngine__PositionAlreadyExists();

        bytes32 salt = keccak256(abi.encodePacked(user));

        // 部署代理合约
        bytes memory initData = abi.encodeWithSelector(
            UserPosition.initialize.selector,
            user,
            address(this),
            user
        );

        UserPosition userPosition = new UserPosition{salt: salt}();

        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(
            address(userPosition),
            initData
        );

        address positionAddress = address(proxy);
        userToPosition[user] = positionAddress;
        positionToUser[positionAddress] = user;

        return positionAddress;
    }

    function bridge(uint256 amount) internal {
        usdc.approve(address(tokenMessenger), amount);
        tokenMessenger.depositForBurn(amount, 5, solanaAddress, address(usdc));
    }

    /// @notice 更新平台费用比例
    /// @dev 只有合约所有者可以调用
    /// @param newFeePercentage 新的费用比例，基点制(10000 = 100%)
    function updatePlatformFee(uint256 newFeePercentage) external onlySigner {
        if (newFeePercentage > BASIS_POINTS)
            revert StrategyEngine__InvalidFeePercentage();

        uint256 oldFee = platformFeePercentage;
        platformFeePercentage = newFeePercentage;

        emit PlatformFeeUpdated(oldFee, newFeePercentage);
    }

    /// @notice 获取当前平台费用比例
    /// @return 当前费用比例，基点制(10000 = 100%)
    function getPlatformFee() external view returns (uint256) {
        return platformFeePercentage;
    }

    /// @notice 获取当前实现合约地址
    function implementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }
}
