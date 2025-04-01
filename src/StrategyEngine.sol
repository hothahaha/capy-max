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

import {IAavePool} from "./interfaces/aave/IAavePool.sol";
import {IAaveOracle} from "./interfaces/aave/IAaveOracle.sol";
import {IPoolDataProvider} from "./interfaces/aave/IAaveProtocolDataProvider.sol";
import {ITokenMessenger} from "./interfaces/cctp/ITokenMessenger.sol";
import {CpToken} from "./tokens/CpToken.sol";
import {Vault} from "./vault/Vault.sol";
import {UserPosition} from "./UserPosition.sol";
import {IStrategyEngine} from "./interfaces/IStrategyEngine.sol";
import {ISafe} from "./interfaces/safe/ISafe.sol";
import {StrategyLib} from "./libraries/StrategyLib.sol";
import {ICpToken} from "./interfaces/ICpToken.sol";

/// @title StrategyEngine
/// @notice Manages yield generation through AAVE and HyperLiquid
contract StrategyEngine is
    IStrategyEngine,
    Initializable,
    UUPSUpgradeableBase,
    ReentrancyGuardUpgradeable
{
    using SafeERC20 for IERC20;
    using StrategyLib for *;

    //--------------------------------------------------------------------------
    // Type declarations
    //--------------------------------------------------------------------------

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
        bool isWithdrawn; // 是否已取款
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

    struct WithdrawalInfo {
        TokenType tokenType;
        address user;
        uint256 amount;
    }

    struct RepayInfo {
        address user;
        uint256 amount;
    }

    //--------------------------------------------------------------------------
    // State variables
    //--------------------------------------------------------------------------

    // Constants
    uint256 public constant BASIS_POINTS = 10000; // 100%
    uint256 public immutable BATCH_SIZE = 10;

    // Core state variables
    uint256 private platformFeePercentage;
    uint256 public defaultLiquidationThreshold;
    bytes32 private solanaAddress;
    address private safeWallet;

    // Token and protocol contracts
    IERC20 public wbtc;
    IERC20 public usdc;
    IAavePool public aavePool;
    IAaveOracle public aaveOracle;
    IPoolDataProvider public aaveProtocolDataProvider;
    CpToken public cpToken;
    Vault public vault;

    // Combined user state
    struct UserState {
        UserInfo info;
        RepayState repayState;
        address position;
    }

    // User data mappings
    mapping(address => UserState) private userStates;
    mapping(address => uint256) private userIndices;

    // User array and batch processing
    address[] private allUsers;
    uint256 private lastHealthCheckTimestamp;
    uint256 public currentBatchIndex;

    //--------------------------------------------------------------------------
    // Events
    //--------------------------------------------------------------------------

    event Deposited(
        bytes32 indexed depositId,
        address indexed user,
        TokenType tokenType,
        uint256 amount,
        uint256 borrowAmount,
        uint256 timestamp
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
        uint256 timestamp,
        uint256 healthFactor
    );

    //--------------------------------------------------------------------------
    // Errors
    //--------------------------------------------------------------------------

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
    error StrategyEngine__InvalidImplementation();
    error StrategyEngine__NoUserPosition();
    error StrategyEngine__InvalidRepayAmount();
    error StrategyEngine__NotSafeSigner();
    error StrategyEngine__InsufficientContractBalance();
    error StrategyEngine__InvalidInput();
    error StrategyEngine__InsufficientAmount();
    error StrategyEngine__WithdrawalNeedRepayAmountLess();

    //--------------------------------------------------------------------------
    // Modifiers
    //--------------------------------------------------------------------------

    modifier onlySafeSigner() {
        bool isSigner = false;
        address[] memory owners = ISafe(safeWallet).getOwners();

        for (uint i = 0; i < owners.length; i++) {
            if (owners[i] == msg.sender) {
                isSigner = true;
                break;
            }
        }

        if (!isSigner) revert StrategyEngine__NotSafeSigner();
        _;
    }

    //--------------------------------------------------------------------------
    // Constructor
    //--------------------------------------------------------------------------

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    //--------------------------------------------------------------------------
    // External Functions
    //--------------------------------------------------------------------------

    /**
     * @notice Initialize the contract with required parameters
     * @param params Initialization parameters
     */
    function initialize(EngineInitParams memory params) external initializer {
        __UUPSUpgradeableBase_init(msg.sender);
        __ReentrancyGuard_init();

        // Set initial platform fee
        platformFeePercentage = 1000;
        wbtc = IERC20(params.wbtc);
        usdc = IERC20(params.usdc);
        aavePool = IAavePool(params.aavePool);
        aaveOracle = IAaveOracle(params.aaveOracle);
        aaveProtocolDataProvider = IPoolDataProvider(params.aaveProtocolDataProvider);
        cpToken = CpToken(params.cpToken);
        vault = Vault(params.vault);
        safeWallet = params.safeWallet;
        defaultLiquidationThreshold = 156;

        transferUpgradeRights(safeWallet);
    }

    /**
     * @notice Deposit tokens into the strategy
     */
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

    /**
     * @notice Batch withdraw function to process multiple withdrawals at once
     * @param users Array of user addresses
     * @param amounts Array of withdrawal amounts
     * @return profits Array of user profits for each withdrawal
     */
    function withdrawBatch(
        address[] calldata users,
        uint256[] calldata amounts
    ) external nonReentrant onlySafeSigner returns (uint256[] memory profits) {
        uint256 length = users.length;
        if (length != amounts.length) revert StrategyEngine__InvalidInput();

        profits = new uint256[](length);

        // Calculate total withdrawal amount to check against contract balance
        uint256 totalWithdrawalAmount = 0;
        for (uint256 i = 0; i < length; i++) {
            if (amounts[i] == 0) revert StrategyEngine__InvalidAmount();
            totalWithdrawalAmount += amounts[i];
        }

        // Check if contract has enough balance for all withdrawals
        uint256 engineBalance = usdc.balanceOf(address(this));
        if (engineBalance < totalWithdrawalAmount)
            revert StrategyEngine__InsufficientContractBalance();

        // Process each withdrawal
        for (uint256 i = 0; i < length; i++) {
            profits[i] = _withdraw(users[i], amounts[i]);
        }

        return profits;
    }

    /**
     * @notice Create a user position
     */
    function createUserPosition() external {
        _createUserPosition(msg.sender);
    }

    /**
     * @notice Update platform fee percentage
     */
    function updatePlatformFee(uint256 newFeePercentage) external onlySafeSigner {
        if (newFeePercentage > BASIS_POINTS) revert StrategyEngine__InvalidFeePercentage();

        uint256 oldFee = platformFeePercentage;
        platformFeePercentage = newFeePercentage;

        emit PlatformFeeUpdated(oldFee, newFeePercentage);
    }

    /**
     * @notice Batch repay borrowed amounts for multiple users
     * @param repayInfos Array of repay information containing user and repay amount
     * @return actualRepayAmounts Array of actual repay amounts for each user
     */
    function repayBorrowBatch(
        RepayInfo[] calldata repayInfos
    ) external nonReentrant onlySafeSigner returns (uint256[] memory actualRepayAmounts) {
        uint256 length = repayInfos.length;
        actualRepayAmounts = new uint256[](length);

        // Process each repayment
        for (uint256 i = 0; i < length; i++) {
            RepayInfo calldata info = repayInfos[i];
            actualRepayAmounts[i] = _repayBorrow(info.user, info.amount);
        }

        return actualRepayAmounts;
    }

    /**
     * @notice Repay borrowed amount for a single user
     * @dev Made internal and replaced by repayBorrowBatch for external calls
     * @param user The user whose borrow will be repaid
     * @param repayAmount The amount to repay
     * @return The actual amount repaid
     */
    function _repayBorrow(address user, uint256 repayAmount) internal returns (uint256) {
        // Validate inputs
        if (repayAmount == 0) revert StrategyEngine__InvalidAmount();

        address userPosition = _getUserPosition(user, true);

        UserState storage state = userStates[user];
        if (repayAmount > state.info.totalBorrowAmount) revert StrategyEngine__InvalidRepayAmount();

        // calculate the amount to repay to Aave
        uint256 aaveDebtAmount = _calculateRepayAmount(address(usdc), userPosition);

        uint256 actualRepayAmount;

        // if the repayment amount is enough to repay the Aave debt
        if (repayAmount >= aaveDebtAmount) {
            // execute the repayment
            _executeRepay(userPosition, aaveDebtAmount);
            actualRepayAmount = aaveDebtAmount;

            // calculate the remaining USDC as profit
            uint256 remainingUsdc = repayAmount - aaveDebtAmount;

            // withdraw the WBTC principal from Aave
            uint256 wbtcAmount = state.info.totalWbtcDeposited;
            UserPosition(payable(userPosition)).executeAaveWithdraw(
                address(aavePool),
                address(wbtc),
                wbtcAmount,
                address(this)
            );

            // handle the profit
            uint256 userProfit = _handleProfit(remainingUsdc);

            // update the repayState
            state.repayState = RepayState({
                principal: wbtcAmount,
                profit: userProfit,
                hasRepaid: true
            });

            // update the user info
            state.info.totalWbtcDeposited = 0;
            state.info.totalBorrowAmount = 0;
        } else {
            // normal repayment process
            actualRepayAmount = _executeRepay(userPosition, repayAmount);
            state.info.totalBorrowAmount -= actualRepayAmount;
        }

        (, , , , , uint256 healthFactor) = _getUserAccountData(userPosition);

        emit BorrowCapacityUpdated(
            user,
            state.info.totalWbtcDeposited,
            state.info.totalBorrowAmount + actualRepayAmount,
            state.info.totalBorrowAmount,
            actualRepayAmount,
            false,
            block.timestamp,
            healthFactor
        );

        return actualRepayAmount;
    }

    /**
     * @notice Withdraw funds for a user
     */
    function withdrawByUser() external nonReentrant {
        address user = msg.sender;
        RepayState storage state = userStates[user].repayState;
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

    /**
     * @notice Update borrow capacity for a specific user
     */
    function updateBorrowCapacity(address user) external {
        _updateBorrowCapacity(user);
    }

    /**
     * @notice Generate a deposit ID
     */
    function _generateDepositId(
        address user,
        TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return
            StrategyLib.generateDepositId(
                user,
                StrategyLib.TokenType(uint(tokenType)),
                amount,
                timestamp
            );
    }

    /**
     * @notice Calculate borrow amount for a user
     */
    function calculateBorrowAmount(address user) external view returns (uint256) {
        return _calculateBorrowAmount(user);
    }

    /**
     * @notice Get user deposit records
     */
    function getUserDepositRecords(address user) external view returns (DepositRecord[] memory) {
        return userStates[user].info.deposits;
    }

    /**
     * @notice Get user total deposits and borrows
     */
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
        UserState storage state = userStates[user];
        return (
            state.info.totalWbtcDeposited,
            state.info.totalUsdcDeposited,
            state.info.totalBorrowAmount,
            state.info.lastDepositTime
        );
    }

    /**
     * @notice Get platform fee percentage
     */
    function getPlatformFee() external view returns (uint256) {
        return platformFeePercentage;
    }

    /**
     * @notice Get default liquidation threshold
     */
    function getDefaultLiquidationThreshold() external view returns (uint256) {
        return defaultLiquidationThreshold;
    }

    /**
     * @notice Get USDC balance of the contract
     */
    function getUSDCBalance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    /**
     * @notice Get WBTC address
     */
    function getWBTCAddress() external view returns (address) {
        return address(wbtc);
    }

    /**
     * @notice Get USDC address
     */
    function getUSDCAddress() external view returns (address) {
        return address(usdc);
    }

    /**
     * @notice Get Aave pool address
     */
    function getAavePoolAddress() external view returns (address) {
        return address(aavePool);
    }

    /**
     * @notice Get Aave oracle address
     */
    function getAaveOracleAddress() external view returns (address) {
        return address(aaveOracle);
    }

    /**
     * @notice Get vault address
     */
    function getVaultAddress() external view returns (address) {
        return address(vault);
    }

    /**
     * @notice Get user position address
     */
    function getUserPositionAddress(address user) external view returns (address) {
        return userStates[user].position;
    }

    //--------------------------------------------------------------------------
    // Public Functions
    //--------------------------------------------------------------------------

    /**
     * @notice Schedule health check for users in batches
     */
    function scheduledHealthCheck() public {
        uint256 endIndex = Math.min(currentBatchIndex + BATCH_SIZE, allUsers.length);

        // Process users in current batch
        for (uint256 i = currentBatchIndex; i < endIndex; i++) {
            address user = allUsers[i];
            if (userStates[user].position != address(0)) {
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

    /**
     * @notice Get user account data from Aave
     */
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
        address userPosition = userStates[user].position;
        return _getUserAccountData(userPosition);
    }

    /**
     * @notice Calculate repay amount for a user
     */
    function calculateRepayAmount(address asset, address user) public view returns (uint256) {
        return StrategyLib.calculateRepayAmount(asset, user, aaveProtocolDataProvider);
    }

    /**
     * @notice Get user account data directly from Aave
     */
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

    //--------------------------------------------------------------------------
    // Internal Functions
    //--------------------------------------------------------------------------

    /**
     * @notice Internal function to process a single withdrawal
     * @param user Address of the user
     * @param amount Amount to withdraw in USDC
     * @return userProfit Profit earned by the user
     */
    function _withdraw(address user, uint256 amount) internal returns (uint256 userProfit) {
        UserState storage state = userStates[user];
        if (state.info.deposits.length == 0) revert StrategyEngine__NoDeposit();

        // get total wbtc, usdc and borrow amount
        (
            uint256 totalWbtcAmount,
            uint256 totalUsdcAmount,
            uint256 totalBorrowAmount
        ) = _calculateWithdrawalAmounts(state.info);

        if (totalWbtcAmount == 0 && totalUsdcAmount == 0) {
            revert StrategyEngine__NoDeposit();
        }

        // ensure the amount is enough to handle all withdrawals
        if (amount < totalBorrowAmount + totalUsdcAmount) {
            revert StrategyEngine__InsufficientAmount();
        }

        // handle wbtc deposit and aave repayment
        (uint256 amountUsdcAfterRepay, ) = StrategyLib.handleWbtcWithdrawal(
            usdc,
            wbtc,
            user,
            amount,
            totalWbtcAmount,
            state.position,
            aaveProtocolDataProvider,
            aavePool
        );

        // handle usdc deposit and calculate profit
        userProfit = StrategyLib.handleUsdcWithdrawalAndProfit(
            usdc,
            user,
            amountUsdcAfterRepay,
            totalUsdcAmount,
            platformFeePercentage,
            address(vault),
            ICpToken(address(cpToken))
        );

        // mark all deposits as withdrawn
        _markDepositsAsWithdrawn(state.info);

        // Update state
        state.info.totalWbtcDeposited = 0;
        state.info.totalUsdcDeposited = 0;
        state.info.totalBorrowAmount = 0;

        emit Withdrawn(user, amount, userProfit);
        return userProfit;
    }

    /**
     * @notice Calculate total withdrawal amounts for a user
     */
    function _calculateWithdrawalAmounts(
        UserInfo storage info
    )
        internal
        view
        returns (uint256 totalWbtcAmount, uint256 totalUsdcAmount, uint256 totalBorrowAmount)
    {
        for (uint256 i = 0; i < info.deposits.length; i++) {
            DepositRecord storage userDeposit = info.deposits[i];
            if (!userDeposit.isWithdrawn) {
                if (userDeposit.tokenType == TokenType.WBTC) {
                    totalWbtcAmount += userDeposit.amount;
                    totalBorrowAmount += userDeposit.borrowAmount;
                } else {
                    totalUsdcAmount += userDeposit.amount;
                }
            }
        }
        return (totalWbtcAmount, totalUsdcAmount, totalBorrowAmount);
    }

    /**
     * @notice Update borrow capacity for a user
     */
    function _updateBorrowCapacity(address user) internal nonReentrant {
        address userPosition = _getUserPosition(user, true);

        // Get user's current info
        UserState storage state = userStates[user];
        uint256 currentWbtc = state.info.totalWbtcDeposited;
        uint256 currentBorrowAmount = state.info.totalBorrowAmount;

        // Calculate new borrow capacity
        uint256 newBorrowAmount = _calculateBorrowAmount(userPosition);

        if (newBorrowAmount > currentBorrowAmount) {
            // Can borrow more
            uint256 additionalBorrow = newBorrowAmount - currentBorrowAmount;

            // Execute additional borrow
            _executeBorrow(userPosition, additionalBorrow);

            // Update user info
            state.info.totalBorrowAmount = newBorrowAmount;

            (, , , , , uint256 healthFactor) = _getUserAccountData(userPosition);

            emit BorrowCapacityUpdated(
                user,
                currentWbtc,
                currentBorrowAmount,
                newBorrowAmount,
                additionalBorrow,
                true,
                block.timestamp,
                healthFactor
            );
        } else if (newBorrowAmount < currentBorrowAmount) {
            // Need to repay
            uint256 repayAmount = currentBorrowAmount - newBorrowAmount;

            (, , , , , uint256 healthFactor) = _getUserAccountData(userPosition);

            emit BorrowCapacityUpdated(
                user,
                currentWbtc,
                currentBorrowAmount,
                newBorrowAmount,
                repayAmount,
                false,
                block.timestamp,
                healthFactor
            );
        }
    }

    /**
     * @notice Handle WBTC deposit
     */
    function _handleWbtcDeposit(
        uint256 amount,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // Get or create user position
        address userPosition = userStates[msg.sender].position;
        if (userPosition == address(0)) {
            userPosition = _createUserPosition(msg.sender);
        }

        // Use permit to authorize
        IERC20Permit(address(wbtc)).permit(msg.sender, address(this), amount, deadline, v, r, s);

        // Transfer WBTC to user position and deposit into Aave
        wbtc.safeTransferFrom(msg.sender, userPosition, amount);

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
            referralCode
        );

        // Update user information
        _updateUserInfo(msg.sender, TokenType.WBTC, amount, borrowAmount);

        bytes32 depositId = _generateDepositId(msg.sender, TokenType.WBTC, amount, block.timestamp);

        emit Deposited(
            depositId,
            msg.sender,
            TokenType.WBTC,
            amount,
            borrowAmount,
            block.timestamp
        );
    }

    /**
     * @notice Handle USDC deposit
     */
    function _handleUsdcDeposit(uint256 amount) internal {
        // Transfer USDC
        StrategyLib.transferUsdc(usdc, msg.sender, address(this), amount);

        // Update user information
        _updateUserInfo(msg.sender, TokenType.USDC, amount, 0);

        bytes32 depositId = _generateDepositId(msg.sender, TokenType.USDC, amount, block.timestamp);

        emit Deposited(depositId, msg.sender, TokenType.USDC, amount, 0, block.timestamp);
    }

    /**
     * @notice Update user information after deposit
     */
    function _updateUserInfo(
        address user,
        TokenType tokenType,
        uint256 depositAmount,
        uint256 borrowAmount
    ) internal {
        UserState storage state = userStates[user];

        // Create new deposit record
        DepositRecord memory newDeposit = DepositRecord({
            depositId: _generateDepositId(user, tokenType, depositAmount, block.timestamp),
            tokenType: tokenType,
            amount: depositAmount,
            timestamp: block.timestamp,
            borrowAmount: borrowAmount,
            isWithdrawn: false
        });

        // Add deposit record
        state.info.deposits.push(newDeposit);

        // Update total amount based on token type
        if (tokenType == TokenType.WBTC) {
            state.info.totalWbtcDeposited += depositAmount;
        } else {
            state.info.totalUsdcDeposited += depositAmount;
        }

        state.info.totalBorrowAmount += borrowAmount;
        state.info.lastDepositTime = block.timestamp;
    }

    /**
     * @notice Calculate borrow amount for a user
     */
    function _calculateBorrowAmount(address user) internal view returns (uint256) {
        (
            uint256 totalCollateralBase,
            uint256 totalDebtBase,
            ,
            uint256 currentLiquidationThreshold,
            ,

        ) = _getUserAccountData(user);

        return
            StrategyLib.calculateBorrowAmount(
                aaveOracle,
                address(usdc),
                totalDebtBase,
                totalCollateralBase,
                currentLiquidationThreshold,
                defaultLiquidationThreshold
            );
    }

    /**
     * @notice Calculate repay amount for a user
     */
    function _calculateRepayAmount(address asset, address user) internal view returns (uint256) {
        return StrategyLib.calculateRepayAmount(asset, user, aaveProtocolDataProvider);
    }

    /**
     * @notice Create a user position
     */
    function _createUserPosition(address user) internal returns (address) {
        if (userStates[user].position != address(0)) revert StrategyEngine__PositionAlreadyExists();

        bytes32 salt = keccak256(abi.encodePacked(user));

        // Deploy proxy contract
        bytes memory initData = abi.encodeWithSelector(
            UserPosition.initialize.selector,
            user,
            address(this),
            user,
            safeWallet
        );

        UserPosition userPosition = new UserPosition{salt: salt}();

        ERC1967Proxy proxy = new ERC1967Proxy{salt: salt}(address(userPosition), initData);

        address positionAddress = address(proxy);
        userStates[user].position = positionAddress;

        // Add user to array
        _addUserToArray(user);

        return positionAddress;
    }

    /**
     * @notice Add user to array
     */
    function _addUserToArray(address user) internal {
        if (userIndices[user] == 0 && allUsers.length > 0 && allUsers[0] != user) {
            userIndices[user] = allUsers.length;
            allUsers.push(user);
        } else if (allUsers.length == 0) {
            userIndices[user] = 0;
            allUsers.push(user);
        }
    }

    /**
     * @notice Transfer USDC between addresses
     */
    function _transferUsdc(address from, address to, uint256 amount) internal {
        StrategyLib.transferUsdc(usdc, from, to, amount);
    }

    /**
     * @notice Handle profit from withdrawal
     */
    function _handleProfit(uint256 totalProfit) internal returns (uint256 userProfit) {
        return
            StrategyLib.handleProfit(
                totalProfit,
                platformFeePercentage,
                usdc,
                address(vault),
                ICpToken(address(cpToken)),
                msg.sender
            );
    }

    /**
     * @notice Execute repayment to Aave
     */
    function _executeRepay(address userPosition, uint256 repayAmount) internal returns (uint256) {
        return StrategyLib.executeRepay(usdc, userPosition, address(aavePool), repayAmount);
    }

    /**
     * @notice Execute borrowing from Aave
     */
    function _executeBorrow(address userPosition, uint256 borrowAmount) internal returns (uint256) {
        return StrategyLib.executeBorrow(usdc, userPosition, address(aavePool), borrowAmount);
    }

    /**
     * @notice Get user position address
     */
    function _getUserPosition(
        address user,
        bool isForBorrowCapacity
    ) internal view returns (address) {
        address userPosition = userStates[user].position;
        if (userPosition == address(0)) {
            if (isForBorrowCapacity) {
                revert StrategyEngine__NoUserPosition();
            } else {
                revert StrategyEngine__PositionNotFound();
            }
        }
        return userPosition;
    }

    /**
     * @notice Get user position address (wrapper function)
     */
    function _getUserPosition(address user) internal view returns (address) {
        return _getUserPosition(user, false);
    }

    /**
     * @notice Mark all deposits as withdrawn
     */
    function _markDepositsAsWithdrawn(UserInfo storage info) internal {
        for (uint256 i = 0; i < info.deposits.length; i++) {
            info.deposits[i].isWithdrawn = true;
        }
    }
}
