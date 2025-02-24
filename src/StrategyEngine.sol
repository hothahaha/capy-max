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
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

import {IAavePool} from "./aave/interface/IAavePool.sol";
import {IAaveOracle} from "./aave/interface/IAaveOracle.sol";
import {IPoolDataProvider} from "./aave/interface/IAaveProtocolDataProvider.sol";
import {ITokenMessenger} from "./cctp/interface/ITokenMessenger.sol";
import {CpToken} from "./tokens/CpToken.sol";
import {Vault} from "./vault/Vault.sol";
import {UserPosition} from "./UserPosition.sol";
import {MultiSig} from "./access/MultiSig.sol";
import {SignerManager} from "./access/SignerManager.sol";
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
    uint256 private constant BASIS_POINTS = 10000; // 100%

    uint256 private platformFeePercentage;
    uint256 private defaultLiquidationThreshold;
    bytes32 private solanaAddress;

    // Token and protocol contracts
    IERC20 public wbtc;
    IERC20 public usdc;
    IAavePool public aavePool;
    IAaveOracle public aaveOracle;
    IPoolDataProvider public aaveProtocolDataProvider;
    ITokenMessenger public tokenMessenger;
    CpToken public cpToken;
    MultiSig public multiSig;
    SignerManager public signerManager;

    // Add token type enum
    enum TokenType {
        WBTC,
        USDC
    }

    // Modify DepositRecord structure, add token type
    struct DepositRecord {
        bytes32 depositId;
        TokenType tokenType;
        uint256 amount;
        uint256 timestamp;
        uint256 borrowAmount;
    }

    // Modify UserInfo structure
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
    event BorrowCapacityUpdated(
        address indexed user,
        uint256 wbtcAmount,
        uint256 originalBorrowAmount,
        uint256 newBorrowAmount,
        uint256 difference,
        bool isIncrease,
        uint256 timestamp
    );

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
    error StrategyEngine__NoUserPosition();
    error StrategyEngine__InvalidRepayAmount();
    // Add status variables
    Vault public vault;

    // Add user position mapping
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

        // Set initial platform fee
        platformFeePercentage = 1000;
        solanaAddress = params.solanaAddress;
        wbtc = IERC20(params.wbtc);
        usdc = IERC20(params.usdc);
        aavePool = IAavePool(params.aavePool);
        aaveOracle = IAaveOracle(params.aaveOracle);
        aaveProtocolDataProvider = IPoolDataProvider(params.aaveProtocolDataProvider);
        tokenMessenger = ITokenMessenger(params.tokenMessenger);
        cpToken = CpToken(params.cpToken);
        vault = Vault(params.vault);
        multiSig = MultiSig(params.multiSig);
        signerManager = SignerManager(address(multiSig.getSignerManager()));

        defaultLiquidationThreshold = 156;

        transferUpgradeRights(address(multiSig));
    }

    function generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return _generateDepositId(user, tokenType, amount, timestamp);
    }

    /// @dev Generate unique depositId
    function _generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, tokenType, amount, timestamp));
    }

    /// @notice Deposit function
    /// @dev Depending on the type of token deposited, if it is WBTC, it needs to be authorized, and then deposited into Aave
    /// @dev If it is USDC, it is directly deposited into the current contract
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

    /// @dev Handle WBTC deposit
    function _handleWbtcDeposit(
        uint256 amount,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // Get or create user position
        address userPosition = userToPosition[msg.sender];
        if (userPosition == address(0)) {
            userPosition = _createUserPosition(msg.sender);
        }

        // Use permit to authorize
        IERC20Permit(address(wbtc)).permit(msg.sender, address(this), amount, deadline, v, r, s);

        // Transfer WBTC to contract
        wbtc.safeTransferFrom(msg.sender, address(this), amount);

        // Transfer WBTC to user position and deposit into Aave
        wbtc.safeTransfer(userPosition, amount);
        UserPosition(payable(userPosition)).executeAaveDeposit(
            address(aavePool),
            address(wbtc),
            amount,
            referralCode
        );

        // Calculate and borrow USDC
        uint256 borrowAmount = _calculateBorrowAmount(userPosition);
        UserPosition(payable(userPosition)).executeBorrow(
            address(aavePool),
            address(usdc),
            borrowAmount,
            2, // Variable rate
            0 // referralCode
        );
        usdc.safeTransferFrom(userPosition, address(this), borrowAmount);

        // Update user information
        _updateUserInfo(msg.sender, TokenType.WBTC, amount, borrowAmount);

        bytes32 depositId = _generateDepositId(msg.sender, TokenType.WBTC, amount, block.timestamp);

        emit Deposited(depositId, msg.sender, TokenType.WBTC, amount, borrowAmount);

        bridge(borrowAmount);
    }

    /// @dev handler USDC withdraw
    function _handleUsdcDeposit(uint256 amount) internal {
        // Transfer USDC
        usdc.safeTransferFrom(msg.sender, address(this), amount);

        // Update user information
        _updateUserInfo(msg.sender, TokenType.USDC, amount, 0);

        bytes32 depositId = _generateDepositId(msg.sender, TokenType.USDC, amount, block.timestamp);

        emit Deposited(depositId, msg.sender, TokenType.USDC, amount, 0);

        bridge(amount);
    }

    /// @dev Update user information
    function _updateUserInfo(
        address user,
        TokenType tokenType,
        uint256 depositAmount,
        uint256 borrowAmount
    ) internal {
        UserInfo storage info = userInfo[user];

        // Create new deposit record
        DepositRecord memory newDeposit = DepositRecord({
            depositId: _generateDepositId(user, tokenType, depositAmount, block.timestamp),
            tokenType: tokenType,
            amount: depositAmount,
            timestamp: block.timestamp,
            borrowAmount: borrowAmount
        });

        // Add deposit record
        info.deposits.push(newDeposit);

        // Update total amount based on token type
        if (tokenType == TokenType.WBTC) {
            info.totalWbtcDeposited += depositAmount;
        } else {
            info.totalUsdcDeposited += depositAmount;
        }

        info.totalBorrowAmount += borrowAmount;
        info.lastDepositTime = block.timestamp;
    }

    /// @notice Withdraw function
    /// @dev Depending on the type of token deposited, if it is WBTC, it needs to repay the Aave loan, check the health factor, and retrieve the collateral
    /// @dev If it is USDC, it is directly withdrawn
    /// @dev Calculate profit, calculate platform fee, store platform fee in vault, transfer user profit out
    /// @dev Return user profit and actual Aave repayment amount
    function withdraw(
        TokenType tokenType,
        address user,
        uint256 amount
    ) external nonReentrant returns (uint256 userProfit, uint256 repayAaveAmount) {
        if (amount == 0) revert StrategyEngine__InvalidAmount();

        uint256 engineBalance = usdc.balanceOf(address(this));
        if (engineBalance < amount) revert StrategyEngine__WithdrawAmountTooHigh();

        UserInfo storage info = userInfo[user];
        uint256 profit;
        uint256 withdrawUSDCAmount;

        if (tokenType == TokenType.WBTC) {
            address userPosition = userToPosition[user];
            if (userPosition == address(0)) revert StrategyEngine__PositionNotFound();

            usdc.safeTransfer(userPosition, amount);
            // Repay Aave loan
            uint256 repayAmount = _calculateRepayAmount(address(usdc), userPosition);

            repayAaveAmount = UserPosition(payable(userPosition)).executeRepay(
                address(aavePool),
                address(usdc),
                amount,
                2 // Variable rate
            );

            if (amount >= repayAmount) {
                // Calculate profit
                profit = amount - repayAmount;

                // Transfer remaining USDC to engine
                usdc.safeTransferFrom(userPosition, address(this), profit);

                uint256 wbtcAmount = info.totalWbtcDeposited;

                // Retrieve collateral
                UserPosition(payable(userPosition)).executeAaveWithdraw(
                    address(aavePool),
                    address(wbtc),
                    wbtcAmount,
                    user
                );

                // Update user information
                info.totalWbtcDeposited = 0;
                info.totalBorrowAmount = 0;
            } else {
                info.totalBorrowAmount -= amount;
                return (0, repayAaveAmount);
            }
        } else {
            // Calculate profit
            profit = amount - info.totalUsdcDeposited;

            withdrawUSDCAmount = info.totalUsdcDeposited;

            // Update user information
            info.totalUsdcDeposited = 0;
        }

        if (profit > 0) {
            // Calculate platform fee
            uint256 platformFee = (profit * platformFeePercentage) / BASIS_POINTS;
            userProfit = profit - platformFee;

            // Store platform fee in vault
            if (platformFee > 0) {
                usdc.safeTransfer(address(vault), platformFee);
            }

            withdrawUSDCAmount += userProfit;

            // Transfer user profit
            usdc.safeTransfer(msg.sender, withdrawUSDCAmount);

            // Mint reward token
            cpToken.mint(msg.sender, userProfit);

            return (userProfit, repayAaveAmount);
        }

        emit Withdrawn(msg.sender, amount, profit);
    }

    function createUserPosition() external {
        _createUserPosition(msg.sender);
    }

    function calculateBorrowAmount(address user) external view returns (uint256) {
        return _calculateBorrowAmount(user);
    }

    function _calculateBorrowAmount(address user) internal view returns (uint256) {
        (
            uint256 totalCollateralBase,
            ,
            ,
            uint256 currentLiquidationThreshold,
            ,

        ) = _getUserAccountData(user);

        // Check if user has enough collateral
        if (totalCollateralBase == 0) revert StrategyEngine__NoCollateral();

        // totalCollateralBase * currentLiquidationThreshold / 1.56 = maxBorrowIn
        // 1.56 Default low health threshold
        uint256 maxBorrowIn = (totalCollateralBase * currentLiquidationThreshold) /
            (defaultLiquidationThreshold * 10 ** 2);
        uint256 usdcPrice = aaveOracle.getAssetPrice(address(usdc));
        uint256 borrowAmount = (maxBorrowIn * 10 ** IERC20Metadata(address(usdc)).decimals()) /
            usdcPrice;

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

    function calculateRepayAmount(address asset, address user) public view returns (uint256) {
        return _calculateRepayAmount(asset, user);
    }

    function _calculateRepayAmount(address asset, address user) internal view returns (uint256) {
        (, , uint256 currentVariableDebt, , , , , , ) = aaveProtocolDataProvider.getUserReserveData(
            asset,
            user
        );
        return currentVariableDebt;
    }

    // Add function to get user deposit records
    function getUserDepositRecords(address user) external view returns (DepositRecord[] memory) {
        return userInfo[user].deposits;
    }

    // Modify query function to support different tokens
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
        if (userToPosition[user] != address(0)) revert StrategyEngine__PositionAlreadyExists();

        bytes32 salt = keccak256(abi.encodePacked(user));

        // Deploy proxy contract
        bytes memory initData = abi.encodeWithSelector(
            UserPosition.initialize.selector,
            user,
            address(this),
            user,
            address(multiSig)
        );

        UserPosition userPosition = new UserPosition{salt: salt}();

        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(address(userPosition), initData);

        address positionAddress = address(proxy);
        userToPosition[user] = positionAddress;
        positionToUser[positionAddress] = user;

        return positionAddress;
    }

    function bridge(uint256 amount) internal {
        usdc.approve(address(tokenMessenger), amount);
        tokenMessenger.depositForBurn(amount, 5, solanaAddress, address(usdc));
    }

    /// @notice Update platform fee percentage
    /// @dev Only contract owner can call
    /// @param newFeePercentage New fee percentage, basis points (10000 = 100%)
    function updatePlatformFee(uint256 newFeePercentage) external onlySigner {
        if (newFeePercentage > BASIS_POINTS) revert StrategyEngine__InvalidFeePercentage();

        uint256 oldFee = platformFeePercentage;
        platformFeePercentage = newFeePercentage;

        emit PlatformFeeUpdated(oldFee, newFeePercentage);
    }

    /// @notice Get current platform fee percentage
    /// @return Current fee percentage, basis points (10000 = 100%)
    function getPlatformFee() external view returns (uint256) {
        return platformFeePercentage;
    }

    function getDefaultLiquidationThreshold() external view returns (uint256) {
        return defaultLiquidationThreshold;
    }

    /// @notice Get current implementation contract address
    function implementation() external view returns (address) {
        return ERC1967Utils.getImplementation();
    }

    /// @notice Update user's borrow capacity
    /// @dev Only for users who pledged and borrowed from Aave when depositing,
    /// @dev that is, users in the UserPosition mapping. To obtain the collateral
    /// @dev value of the current user, you can call the _calculateBorrowAmount function
    /// @dev to recalculate, and then obtain the user's current borrowing capacity,
    /// @dev which may be more or less than the historical borrowing amount
    /// @dev 1. When it is more, call Aave's borrowing again to borrow more,
    /// @dev cross-chain and update the user's borrowing information, and record Event
    /// @dev 2. When it is less, record Event, The event records the user's real address,
    /// @dev the amount of wbtc pledged, the original borrowing amount,
    /// @dev the amount to borrow and repay, and the date of the update record
    /// @param user User address
    function updateBorrowCapacity(address user) external nonReentrant {
        address userPosition = userToPosition[user];
        if (userPosition == address(0)) revert StrategyEngine__NoUserPosition();

        // Get user's current info
        UserInfo storage info = userInfo[user];
        uint256 currentWbtc = info.totalWbtcDeposited;
        uint256 currentBorrowAmount = info.totalBorrowAmount;

        // Calculate new borrow capacity
        uint256 newBorrowAmount = _calculateBorrowAmount(userPosition);

        if (newBorrowAmount > currentBorrowAmount) {
            // Can borrow more
            uint256 additionalBorrow = newBorrowAmount - currentBorrowAmount;

            // Execute additional borrow
            UserPosition(payable(userPosition)).executeBorrow(
                address(aavePool),
                address(usdc),
                additionalBorrow,
                2, // Variable rate
                0 // referralCode
            );

            // Transfer USDC to engine and bridge
            usdc.safeTransferFrom(userPosition, address(this), additionalBorrow);
            bridge(additionalBorrow);

            // Update user info
            info.totalBorrowAmount = newBorrowAmount;

            emit BorrowCapacityUpdated(
                user,
                currentWbtc,
                currentBorrowAmount,
                newBorrowAmount,
                additionalBorrow,
                true,
                block.timestamp
            );
        } else if (newBorrowAmount < currentBorrowAmount) {
            // Need to repay
            uint256 repayAmount = currentBorrowAmount - newBorrowAmount;

            emit BorrowCapacityUpdated(
                user,
                currentWbtc,
                currentBorrowAmount,
                newBorrowAmount,
                repayAmount,
                false,
                block.timestamp
            );
        }
    }

    /// @notice Repay borrowed USDC to Aave
    /// @dev Directly calls the repay function in UserPosition to repay Aave
    /// @param user User address
    /// @param repayAmount Amount to repay
    function repayBorrow(address user, uint256 repayAmount) external nonReentrant {
        // Validate inputs
        if (repayAmount == 0) revert StrategyEngine__InvalidAmount();

        address userPosition = userToPosition[user];
        if (userPosition == address(0)) revert StrategyEngine__NoUserPosition();

        UserInfo storage info = userInfo[user];
        if (repayAmount > info.totalBorrowAmount) revert StrategyEngine__InvalidRepayAmount();

        // Transfer USDC to user position for repayment
        usdc.safeTransfer(userPosition, repayAmount);

        // Execute repayment through user position
        uint256 actualRepayAmount = UserPosition(payable(userPosition)).executeRepay(
            address(aavePool),
            address(usdc),
            repayAmount,
            2 // Variable rate
        );

        // Update user borrow info
        info.totalBorrowAmount -= actualRepayAmount;

        emit BorrowCapacityUpdated(
            user,
            info.totalWbtcDeposited,
            info.totalBorrowAmount + actualRepayAmount,
            info.totalBorrowAmount,
            actualRepayAmount,
            false,
            block.timestamp
        );
    }
}
