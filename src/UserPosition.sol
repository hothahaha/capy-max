// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

import {IAavePool} from "./aave/interface/IAavePool.sol";

contract UserPosition is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    using SafeERC20 for IERC20;

    // 将 immutable 变量改为状态变量
    address public strategy;
    address public user;

    error UserPosition__Unauthorized();
    error UserPosition__TransferFailed();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _user) public initializer {
        __Ownable_init(msg.sender); // 设置 strategy 为 owner
        __UUPSUpgradeable_init();

        strategy = msg.sender;
        user = _user;
    }

    /// @notice 实现 UUPS 升级功能
    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {
        // 可以添加额外的升级条件
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
        IAavePool(aavePool).borrow(
            asset,
            amount,
            interestRateMode,
            referralCode,
            address(this)
        );
        IERC20(asset).approve(strategy, type(uint256).max);
    }

    function executeRepay(
        address aavePool,
        address asset,
        uint256 amount,
        uint256 interestRateMode
    ) external onlyStrategy returns (uint256) {
        IERC20(asset).approve(aavePool, amount);
        return
            IAavePool(aavePool).repay(
                asset,
                amount,
                interestRateMode,
                address(this)
            );
    }

    receive() external payable {}
}
