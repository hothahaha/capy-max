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
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

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

    // Type declarations
    enum TokenType {
        WBTC,
        USDC
    }

    struct DepositRecord {
        bytes32 depositId;
        TokenType tokenType;
        uint256 amount;
        uint256 timestamp;
        uint256 borrowAmount;
    }

    struct UserInfo {
        uint256 totalWbtcDeposited;
        uint256 totalUsdcDeposited;
        uint256 totalBorrowAmount;
        uint256 lastDepositTime;
        DepositRecord[] deposits;
    }

    struct RepayState {
        uint256 principal; // WBTC principal
        uint256 profit; // USDC profit
        bool hasRepaid; // has repaid
    }

    // Constants
    uint256 private constant BASIS_POINTS = 10000; // 100%
    uint256 public constant BATCH_SIZE = 10;

    // State variables
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
    Vault public vault;

    // User data mappings
    mapping(address => UserInfo) public userInfo;
    mapping(address => address) public userToPosition;
    mapping(address => address) public positionToUser;
    mapping(address => uint256) public userIndices;
    mapping(address => RepayState) public repayStates;

    // User array and batch processing
    address[] public allUsers;
    uint256 public lastHealthCheckTimestamp;
    uint256 public currentBatchIndex;

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

    // Modifiers
    modifier onlySigner() {
        if (!signerManager.isSigner(msg.sender)) {
            revert StrategyEngine__Unauthorized();
        }
        _;
    }

    // Constructor
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    // Initialization
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

    // External functions - View

    function generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) external pure returns (bytes32) {
        return _generateDepositId(user, tokenType, amount, timestamp);
    }

    function calculateBorrowAmount(address user) external view returns (uint256) {
        return _calculateBorrowAmount(user);
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

    function calculateRepayAmount(address asset, address user) public view returns (uint256) {
        return _calculateRepayAmount(asset, user);
    }

    function getUserDepositRecords(address user) external view returns (DepositRecord[] memory) {
        return userInfo[user].deposits;
    }

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

    function getPlatformFee() external view returns (uint256) {
        return platformFeePercentage;
    }

    function getDefaultLiquidationThreshold() external view returns (uint256) {
        return defaultLiquidationThreshold;
    }

    function getUSDCBalance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    function checkUpkeep(
        bytes calldata /* checkData */
    ) external view returns (bool upkeepNeeded, bytes memory /* performData */) {
        // Check if 1 hour has passed
        upkeepNeeded = (block.timestamp - lastHealthCheckTimestamp) >= 1 hours;
        return (upkeepNeeded, "");
    }

    // External functions - State changing

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
            address userPosition = _getUserPosition(user, false);

            // Repay Aave loan
            uint256 repayAmount = _calculateRepayAmount(address(usdc), userPosition);
            repayAaveAmount = _executeRepay(userPosition, amount);

            if (amount >= repayAmount) {
                // Calculate profit
                profit = amount - repayAmount;

                // Transfer remaining USDC to engine
                _transferUsdc(userPosition, address(this), profit);

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

        (userProfit, ) = _handleProfit(profit, withdrawUSDCAmount);

        emit Withdrawn(msg.sender, amount, profit);

        return (userProfit, repayAaveAmount);
    }

    function createUserPosition() external {
        _createUserPosition(msg.sender);
    }

    function updatePlatformFee(uint256 newFeePercentage) external onlySigner {
        if (newFeePercentage > BASIS_POINTS) revert StrategyEngine__InvalidFeePercentage();

        uint256 oldFee = platformFeePercentage;
        platformFeePercentage = newFeePercentage;

        emit PlatformFeeUpdated(oldFee, newFeePercentage);
    }

    function repayBorrow(address user, uint256 repayAmount) external nonReentrant {
        // Validate inputs
        if (repayAmount == 0) revert StrategyEngine__InvalidAmount();

        address userPosition = _getUserPosition(user, true);

        UserInfo storage info = userInfo[user];
        if (repayAmount > info.totalBorrowAmount) revert StrategyEngine__InvalidRepayAmount();

        // calculate the amount to repay to Aave
        uint256 aaveDebtAmount = _calculateRepayAmount(address(usdc), userPosition);

        // if the repayment amount is enough to repay the Aave debt
        if (repayAmount >= aaveDebtAmount) {
            // execute the repayment
            _executeRepay(userPosition, aaveDebtAmount);

            // calculate the remaining USDC as profit
            uint256 remainingUsdc = repayAmount - aaveDebtAmount;

            // withdraw the WBTC principal from Aave
            uint256 wbtcAmount = info.totalWbtcDeposited;
            UserPosition(payable(userPosition)).executeAaveWithdraw(
                address(aavePool),
                address(wbtc),
                wbtcAmount,
                address(this)
            );

            // handle the profit
            (uint256 userProfit, ) = _handleProfit(remainingUsdc, 0);

            // update the repayState
            repayStates[user] = RepayState({
                principal: wbtcAmount,
                profit: userProfit,
                hasRepaid: true
            });

            // update the user info
            info.totalWbtcDeposited = 0;
            info.totalBorrowAmount = 0;
        } else {
            // normal repayment process
            uint256 actualRepayAmount = _executeRepay(userPosition, repayAmount);
            info.totalBorrowAmount -= actualRepayAmount;
        }

        emit BorrowCapacityUpdated(
            user,
            info.totalWbtcDeposited,
            info.totalBorrowAmount + repayAmount,
            info.totalBorrowAmount,
            repayAmount,
            false,
            block.timestamp
        );
    }

    function withdrawByUser(address user) external nonReentrant {
        RepayState storage state = repayStates[user];
        if (!state.hasRepaid) revert StrategyEngine__NoDeposit();

        uint256 principal = state.principal;
        uint256 profit = state.profit;

        // reset the state
        state.principal = 0;
        state.profit = 0;
        state.hasRepaid = false;

        // transfer the principal and profit
        if (principal > 0) {
            wbtc.safeTransfer(user, principal);
        }
        if (profit > 0) {
            usdc.safeTransfer(user, profit);
        }

        emit Withdrawn(user, principal, profit);
    }

    function performUpkeep(bytes calldata /* performData */) external {
        // Check if 1 hour has passed
        if ((block.timestamp - lastHealthCheckTimestamp) < 1 hours) {
            return;
        }

        // Execute health check
        scheduledHealthCheck();

        // Update last execution time
        lastHealthCheckTimestamp = block.timestamp;
    }

    function updateBorrowCapacity(address user) external {
        _updateBorrowCapacity(user);
    }

    // Public functions

    function scheduledHealthCheck() public {
        uint256 endIndex = Math.min(currentBatchIndex + BATCH_SIZE, allUsers.length);

        // Process users in current batch
        for (uint256 i = currentBatchIndex; i < endIndex; i++) {
            address user = allUsers[i];
            if (userToPosition[user] != address(0)) {
                _updateBorrowCapacity(user);
            }
        }

        // Update start index of next batch
        if (endIndex >= allUsers.length) {
            currentBatchIndex = 0;
        } else {
            currentBatchIndex = endIndex;
        }
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

    // Internal functions

    function _generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, tokenType, amount, timestamp));
    }

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
        borrowAmount = _executeBorrow(userPosition, borrowAmount);

        // Update user information
        _updateUserInfo(msg.sender, TokenType.WBTC, amount, borrowAmount);

        bytes32 depositId = _generateDepositId(msg.sender, TokenType.WBTC, amount, block.timestamp);

        emit Deposited(depositId, msg.sender, TokenType.WBTC, amount, borrowAmount);

        // bridge(borrowAmount);
    }

    function _handleUsdcDeposit(uint256 amount) internal {
        // Transfer USDC
        _transferUsdc(msg.sender, address(this), amount);

        // Update user information
        _updateUserInfo(msg.sender, TokenType.USDC, amount, 0);

        bytes32 depositId = _generateDepositId(msg.sender, TokenType.USDC, amount, block.timestamp);

        emit Deposited(depositId, msg.sender, TokenType.USDC, amount, 0);

        // bridge(amount);
    }

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

    function _calculateRepayAmount(address asset, address user) internal view returns (uint256) {
        (, , uint256 currentVariableDebt, , , , , , ) = aaveProtocolDataProvider.getUserReserveData(
            asset,
            user
        );
        return currentVariableDebt;
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

        // Add user to array
        _addUserToArray(user);

        return positionAddress;
    }

    /* function bridge(uint256 amount) internal {
        usdc.approve(address(tokenMessenger), amount);
        tokenMessenger.depositForBurn(amount, 5, solanaAddress, address(usdc));
    } */

    function _updateBorrowCapacity(address user) internal nonReentrant {
        address userPosition = _getUserPosition(user, true);

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
            _executeBorrow(userPosition, additionalBorrow);

            // Bridge additional borrow
            // bridge(additionalBorrow);

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

    function _addUserToArray(address user) internal {
        if (userIndices[user] == 0 && allUsers.length > 0 && allUsers[0] != user) {
            userIndices[user] = allUsers.length;
            allUsers.push(user);
        } else if (allUsers.length == 0) {
            userIndices[user] = 0;
            allUsers.push(user);
        }
    }

    function _transferUsdc(address from, address to, uint256 amount) internal {
        if (from == address(this)) {
            usdc.safeTransfer(to, amount);
        } else {
            usdc.safeTransferFrom(from, to, amount);
        }
    }

    function _handleProfit(
        uint256 profit,
        uint256 withdrawUSDCAmount
    ) internal returns (uint256 userProfit, uint256 totalWithdrawAmount) {
        if (profit <= 0) return (0, withdrawUSDCAmount);

        // Calculate platform fee
        uint256 platformFee = (profit * platformFeePercentage) / BASIS_POINTS;
        userProfit = profit - platformFee;

        // Store platform fee in vault
        if (platformFee > 0) {
            _transferUsdc(address(this), address(vault), platformFee);
        }

        totalWithdrawAmount = withdrawUSDCAmount + userProfit;

        // Transfer user profit
        _transferUsdc(address(this), msg.sender, totalWithdrawAmount);

        // Mint reward token
        cpToken.mint(msg.sender, userProfit);

        return (userProfit, totalWithdrawAmount);
    }

    function _executeRepay(address userPosition, uint256 repayAmount) internal returns (uint256) {
        _transferUsdc(address(this), userPosition, repayAmount);

        return
            UserPosition(payable(userPosition)).executeRepay(
                address(aavePool),
                address(usdc),
                repayAmount,
                2 // Variable rate
            );
    }

    function _executeBorrow(address userPosition, uint256 borrowAmount) internal returns (uint256) {
        UserPosition(payable(userPosition)).executeBorrow(
            address(aavePool),
            address(usdc),
            borrowAmount,
            2, // Variable rate
            0 // referralCode
        );

        _transferUsdc(userPosition, address(this), borrowAmount);

        return borrowAmount;
    }

    function _getUserPosition(
        address user,
        bool isForBorrowCapacity
    ) internal view returns (address) {
        address userPosition = userToPosition[user];
        if (userPosition == address(0)) {
            if (isForBorrowCapacity) {
                revert StrategyEngine__NoUserPosition();
            } else {
                revert StrategyEngine__PositionNotFound();
            }
        }
        return userPosition;
    }

    function _getUserPosition(address user) internal view returns (address) {
        return _getUserPosition(user, false);
    }
}
