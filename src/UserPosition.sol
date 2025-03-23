// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {UUPSUpgradeableBase} from "./upgradeable/UUPSUpgradeableBase.sol";

import {IAavePool} from "./interfaces/aave/IAavePool.sol";

contract UserPosition is UUPSUpgradeableBase {
    using SafeERC20 for IERC20;

    // Errors
    error UserPosition__Unauthorized();
    error UserPosition__TransferFailed();
    error UserPosition__InvalidAmount();
    error UserPosition__TransferNotAllowed();

    // State variables
    address public strategy;
    address public user;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        address _strategy,
        address _user,
        address _safeWallet
    ) external initializer {
        __UUPSUpgradeableBase_init(initialOwner);
        strategy = _strategy;
        user = _user;
        transferUpgradeRights(_safeWallet);
    }

    modifier onlyStrategy() {
        if (msg.sender != strategy) revert UserPosition__Unauthorized();
        _;
    }

    function executeAaveDeposit(
        address aavePool,
        address wbtc,
        uint256 amount,
        uint16 referralCode
    ) external onlyStrategy {
        IERC20(wbtc).approve(aavePool, amount);
        IAavePool(aavePool).supply(wbtc, amount, address(this), referralCode);
    }

    function executeAaveWithdraw(
        address aavePool,
        address asset,
        uint256 amount,
        address recipient
    ) external onlyStrategy returns (uint256) {
        return IAavePool(aavePool).withdraw(asset, amount, recipient);
    }

    function executeBorrow(
        address aavePool,
        address asset,
        uint256 amount,
        uint256 interestRateMode,
        uint16 referralCode
    ) external onlyStrategy {
        IAavePool(aavePool).borrow(asset, amount, interestRateMode, referralCode, address(this));
        IERC20(asset).approve(strategy, type(uint256).max);
    }

    function executeRepay(
        address aavePool,
        address asset,
        uint256 amount,
        uint256 interestRateMode
    ) external onlyStrategy returns (uint256) {
        IERC20(asset).approve(aavePool, amount);
        return IAavePool(aavePool).repay(asset, amount, interestRateMode, address(this));
    }

    receive() external payable {}
}
