// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeableBase} from "./upgradeable/UUPSUpgradeableBase.sol";
import {ReentrancyGuardUpgradeable} from "@openzeppelin/contracts-upgradeable/utils/ReentrancyGuardUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {IAavePool} from "./interfaces/aave/IAavePool.sol";
import {IAaveOracle} from "./interfaces/aave/IAaveOracle.sol";
import {IPoolDataProvider} from "./interfaces/aave/IAaveProtocolDataProvider.sol";
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

    // Use library types
    using StrategyLib for StrategyLib.UserInfo;
    using StrategyLib for StrategyLib.DepositRecord;
    using StrategyLib for StrategyLib.RepayState;

    // Combined user state
    struct UserState {
        StrategyLib.UserInfo info;
        StrategyLib.RepayState repayState;
        address position;
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
    address private safeWallet;

    // Token and protocol contracts
    IERC20 public wbtc;
    IERC20 public usdc;
    IAavePool public aavePool;
    IAaveOracle public aaveOracle;
    IPoolDataProvider public aaveProtocolDataProvider;
    ICpToken public cpToken;
    Vault public vault;

    // User data mappings
    mapping(address => UserState) private userStates;
    mapping(address => uint256) private userIndices;

    // User array and batch processing
    address[] private allUsers;
    uint256 public currentBatchIndex;

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

    /// @notice Initialize the contract
    /// @param params Initialization parameters containing all necessary contract addresses and configurations
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
        cpToken = ICpToken(params.cpToken);
        vault = Vault(params.vault);
        safeWallet = params.safeWallet;
        defaultLiquidationThreshold = 156;

        transferUpgradeRights(safeWallet);
    }

    /// @notice Deposit WBTC or USDC tokens
    /// @param tokenType Type of token (WBTC/USDC)
    /// @param amount Amount to deposit
    /// @param referralCode Referral code
    /// @param deadline Signature deadline
    /// @param v Signature v value
    /// @param r Signature r value
    /// @param s Signature s value
    function deposit(
        StrategyLib.TokenType tokenType,
        uint256 amount,
        uint16 referralCode,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external payable nonReentrant {
        if (amount == 0) revert StrategyEngine__InvalidAmount();

        if (tokenType == StrategyLib.TokenType.WBTC) {
            _handleWbtcDeposit(amount, referralCode, deadline, v, r, s);
        } else {
            _handleUsdcDeposit(amount, deadline, v, r, s);
        }
    }

    /// @notice Batch withdrawal processing
    /// @param users Array of user addresses
    /// @param amounts Array of withdrawal amounts
    /// @return profits Array of profits for each user
    /// @return successes Array of success flags for each user
    function withdrawBatch(
        address[] calldata users,
        uint256[] calldata amounts
    )
        external
        nonReentrant
        onlySafeSigner
        returns (uint256[] memory profits, bool[] memory successes)
    {
        uint256 length = users.length;
        if (length != amounts.length) revert StrategyEngine__InvalidInput();

        profits = new uint256[](length);
        successes = new bool[](length);

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
            try this._withdraw(users[i], amounts[i]) returns (uint256 profit) {
                profits[i] = profit;
                successes[i] = true;
            } catch {
                profits[i] = 0;
                successes[i] = false;
            }
        }

        return (profits, successes);
    }

    /// @notice Create a user position contract
    function createUserPosition() external {
        _createUserPosition(msg.sender);
    }

    /// @notice Update the platform fee percentage
    /// @param newFeePercentage New fee percentage
    function updatePlatformFee(uint256 newFeePercentage) external onlySafeSigner {
        if (newFeePercentage > BASIS_POINTS) revert StrategyEngine__InvalidFeePercentage();

        uint256 oldFee = platformFeePercentage;
        platformFeePercentage = newFeePercentage;

        emit PlatformFeeUpdated(oldFee, newFeePercentage);
    }

    /// @notice Batch repay borrowings
    /// @param repayInfos Array of repayment information containing user addresses and repayment amounts
    /// @return actualRepayAmounts Array of actual repayment amounts
    function repayBorrowBatch(
        StrategyLib.RepayInfo[] calldata repayInfos
    ) external nonReentrant onlySafeSigner returns (uint256[] memory actualRepayAmounts) {
        uint256 length = repayInfos.length;
        actualRepayAmounts = new uint256[](length);

        // Process each repayment
        for (uint256 i = 0; i < length; i++) {
            StrategyLib.RepayInfo calldata info = repayInfos[i];
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
            state.repayState = StrategyLib.RepayState({
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

        (, , , , , uint256 healthFactor) = getUserAccountData(userPosition);

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

    /// @notice User withdraws repaid funds
    function withdrawByUser() external nonReentrant {
        address user = msg.sender;
        StrategyLib.RepayState storage state = userStates[user].repayState;
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

    /// @notice Update the user's borrowing capacity
    /// @param user User address
    function updateBorrowCapacity(address user) external {
        _updateBorrowCapacity(user);
    }

    /**
     * @notice Generate a deposit ID
     */
    function _generateDepositId(
        address user,
        StrategyLib.TokenType tokenType,
        uint256 amount,
        uint256 timestamp
    ) internal pure returns (bytes32) {
        return StrategyLib.generateDepositId(user, tokenType, amount, timestamp);
    }

    /// @notice Calculate the borrowable amount for a user
    /// @param user User address
    /// @return Borrowable amount
    function calculateBorrowAmount(address user) external view returns (uint256) {
        return _calculateBorrowAmount(user);
    }

    /// @notice Get the user's deposit records
    /// @param user User address
    /// @return Array of deposit records
    function getUserDepositRecords(
        address user
    ) external view returns (StrategyLib.DepositRecord[] memory) {
        return userStates[user].info.deposits;
    }

    /// @notice Get the user's total deposits and borrowings
    /// @param user User address
    /// @return totalWbtc Total WBTC deposits
    /// @return totalUsdc Total USDC deposits
    /// @return totalBorrows Total borrowings
    /// @return lastDepositTime Last deposit time
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

    /// @notice Get the platform fee percentage
    /// @return Current platform fee percentage
    function getPlatformFee() external view returns (uint256) {
        return platformFeePercentage;
    }

    /// @notice Get the default liquidation threshold
    /// @return Default liquidation threshold
    function getDefaultLiquidationThreshold() external view returns (uint256) {
        return defaultLiquidationThreshold;
    }

    /// @notice Get the contract's USDC balance
    /// @return USDC balance
    function getUSDCBalance() external view returns (uint256) {
        return usdc.balanceOf(address(this));
    }

    /// @notice Get the user's position contract address
    /// @param user User address
    /// @return Position contract address
    function getUserPositionAddress(address user) external view returns (address) {
        return userStates[user].position;
    }

    //--------------------------------------------------------------------------
    // Public Functions
    //--------------------------------------------------------------------------

    /// @notice Execute scheduled health checks
    /// @dev Process user health checks in batches, with a maximum of BATCH_SIZE users per batch
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

    /// @notice Get the user's account data from Aave
    /// @param user User address
    /// @return totalCollateralBase Total collateral base
    /// @return totalDebtBase Total debt base
    /// @return availableBorrowsBase Available borrows base
    /// @return currentLiquidationThreshold Current liquidation threshold
    /// @return ltv Loan-to-value ratio
    /// @return healthFactor Health factor
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
        return StrategyLib._getUserAccountData(userPosition, address(aavePool));
    }

    /**
     * @notice Calculate repay amount for a user
     */
    function _calculateRepayAmount(address asset, address user) internal view returns (uint256) {
        return StrategyLib.calculateRepayAmount(asset, user, aaveProtocolDataProvider);
    }

    //--------------------------------------------------------------------------
    // Internal Functions
    //--------------------------------------------------------------------------

    /// @notice Internal function to process a single withdrawal
    /// @param user Address of the user
    /// @param amount Amount to withdraw in USDC
    /// @return userProfit Profit earned by the user
    function _withdraw(address user, uint256 amount) external returns (uint256 userProfit) {
        require(msg.sender == address(this), "Only callable by StrategyEngine");
        UserState storage state = userStates[user];
        if (state.info.deposits.length == 0) revert StrategyEngine__NoDeposit();

        (uint256 totalWbtcAmount, uint256 totalUsdcAmount, uint256 totalBorrowAmount) = StrategyLib
            .calculateWithdrawalAmounts(state.info);

        if (totalWbtcAmount == 0 && totalUsdcAmount == 0) {
            revert StrategyEngine__NoDeposit();
        }

        if (amount < totalBorrowAmount + totalUsdcAmount) {
            revert StrategyEngine__InsufficientAmount();
        }

        uint256 amountUsdcAfterRepay = StrategyLib.handleWbtcWithdrawal(
            usdc,
            wbtc,
            user,
            amount,
            totalWbtcAmount,
            state.position,
            aaveProtocolDataProvider,
            aavePool
        );

        userProfit = StrategyLib.handleUsdcWithdrawalAndProfit(
            usdc,
            user,
            amountUsdcAfterRepay,
            totalUsdcAmount,
            platformFeePercentage,
            address(vault),
            ICpToken(cpToken)
        );

        StrategyLib.markDepositsAsWithdrawn(state.info);

        state.info.totalWbtcDeposited = 0;
        state.info.totalUsdcDeposited = 0;
        state.info.totalBorrowAmount = 0;

        emit Withdrawn(user, amount, userProfit);
        return userProfit;
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

            (, , , , , uint256 healthFactor) = getUserAccountData(userPosition);

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

            (, , , , , uint256 healthFactor) = getUserAccountData(userPosition);

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
        address userPosition = userStates[msg.sender].position;
        if (userPosition == address(0)) {
            userPosition = _createUserPosition(msg.sender);
        }

        IERC20Permit(address(wbtc)).permit(msg.sender, address(this), amount, deadline, v, r, s);

        uint256 borrowAmount = StrategyLib.handleWbtcDeposit(
            wbtc,
            usdc,
            msg.sender,
            userPosition,
            amount,
            referralCode,
            address(aavePool),
            address(aaveOracle),
            defaultLiquidationThreshold
        );

        _updateUserInfo(msg.sender, StrategyLib.TokenType.WBTC, amount, borrowAmount);

        emit Deposited(
            StrategyLib.generateDepositId(
                msg.sender,
                StrategyLib.TokenType.WBTC,
                amount,
                block.timestamp
            ),
            msg.sender,
            StrategyLib.TokenType.WBTC,
            amount,
            borrowAmount,
            block.timestamp
        );
    }

    /**
     * @notice Handle USDC deposit
     */
    function _handleUsdcDeposit(
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        IERC20Permit(address(usdc)).permit(msg.sender, address(this), amount, deadline, v, r, s);

        StrategyLib.handleUsdcDeposit(usdc, msg.sender, address(this), amount);

        _updateUserInfo(msg.sender, StrategyLib.TokenType.USDC, amount, 0);

        emit Deposited(
            StrategyLib.generateDepositId(
                msg.sender,
                StrategyLib.TokenType.USDC,
                amount,
                block.timestamp
            ),
            msg.sender,
            StrategyLib.TokenType.USDC,
            amount,
            0,
            block.timestamp
        );
    }

    /**
     * @notice Update user information after deposit
     */
    function _updateUserInfo(
        address user,
        StrategyLib.TokenType tokenType,
        uint256 depositAmount,
        uint256 borrowAmount
    ) internal {
        UserState storage state = userStates[user];

        // Create new deposit record
        StrategyLib.DepositRecord memory newDeposit = StrategyLib.DepositRecord({
            depositId: StrategyLib.generateDepositId(
                user,
                tokenType,
                depositAmount,
                block.timestamp
            ),
            tokenType: tokenType,
            amount: depositAmount,
            timestamp: block.timestamp,
            borrowAmount: borrowAmount,
            isWithdrawn: false
        });

        // Add deposit record
        state.info.deposits.push(newDeposit);

        // Update total amount based on token type
        if (tokenType == StrategyLib.TokenType.WBTC) {
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

        ) = StrategyLib._getUserAccountData(user, address(aavePool));

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

    /// @notice Emergency withdrawal of WBTC
    /// @dev Only callable by SafeSigner, used for handling emergency situations where deposits fail
    /// @param withdrawalInfos Array of emergency withdrawal information
    /// @return amounts Array of actual withdrawal amounts
    function emergencyWbtcWithdrawal(
        EmergencyWithdrawalInfo[] calldata withdrawalInfos
    ) external nonReentrant onlySafeSigner returns (uint256[] memory amounts) {
        uint256 length = withdrawalInfos.length;
        amounts = new uint256[](length);

        // Calculate total withdrawal amount
        uint256 totalWithdrawalAmount = 0;
        for (uint256 i = 0; i < length; i++) {
            if (withdrawalInfos[i].amount == 0) revert StrategyEngine__InvalidAmount();
            totalWithdrawalAmount += withdrawalInfos[i].amount;
        }

        // Check if contract has enough WBTC balance
        uint256 engineBalance = wbtc.balanceOf(address(this));
        if (engineBalance < totalWithdrawalAmount)
            revert StrategyEngine__InsufficientContractBalance();

        // Process each withdrawal
        for (uint256 i = 0; i < length; i++) {
            EmergencyWithdrawalInfo calldata info = withdrawalInfos[i];

            // Transfer WBTC to user
            wbtc.safeTransfer(info.user, info.amount);
            amounts[i] = info.amount;

            // Emit event for tracking
            emit EmergencyAction(info.user, info.amount);
        }

        return amounts;
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
                cpToken,
                msg.sender
            );
    }
}
