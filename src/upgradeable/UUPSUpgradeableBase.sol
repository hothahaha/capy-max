// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

/// @title UUPSUpgradeableBase
/// @notice Base contract for upgradeable contracts using UUPS pattern
/// @dev Manages upgrade rights and authorization
abstract contract UUPSUpgradeableBase is UUPSUpgradeable, OwnableUpgradeable {
    error UUPSUpgradeableBase__Unauthorized();
    error UUPSUpgradeableBase__InvalidImplementation();
    error UUPSUpgradeableBase__InvalidUpgradeRightsOwner();

    address private _upgradeRightsOwner;

    event UpgradeRightsTransferred(address indexed from, address indexed to);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the upgradeable contract
    /// @param initialOwner Address of the initial owner
    function __UUPSUpgradeableBase_init(address initialOwner) internal onlyInitializing {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        _upgradeRightsOwner = initialOwner;
    }

    /// @notice Transfer upgrade rights to a new owner
    /// @dev Internal method, only called during initialization or by admin functions
    /// @param newOwner Address of the new owner
    function transferUpgradeRights(address newOwner) internal {
        if (newOwner == address(0)) {
            revert UUPSUpgradeableBase__InvalidUpgradeRightsOwner();
        }
        if (newOwner == _upgradeRightsOwner) {
            revert UUPSUpgradeableBase__InvalidUpgradeRightsOwner();
        }

        address oldOwner = _upgradeRightsOwner;
        _upgradeRightsOwner = newOwner;
        emit UpgradeRightsTransferred(oldOwner, newOwner);
    }

    /// @notice Get upgrade rights owner
    /// @return Address of the current upgrade rights owner
    function upgradeRightsOwner() public view returns (address) {
        return _upgradeRightsOwner;
    }

    /// @notice Get current implementation contract address
    /// @return The address of the current implementation contract
    function implementation() public view returns (address) {
        return ERC1967Utils.getImplementation();
    }

    /// @notice Authorize an upgrade to a new implementation
    /// @param newImplementation Address of the new implementation
    function _authorizeUpgrade(address newImplementation) internal view override {
        // Check if new implementation contract address is zero address
        if (newImplementation == address(0)) {
            revert UUPSUpgradeableBase__InvalidImplementation();
        }

        // Check if new implementation address is the same as current implementation address
        if (newImplementation == ERC1967Utils.getImplementation()) {
            revert UUPSUpgradeableBase__InvalidImplementation();
        }

        // Ensure caller is upgrade rights owner
        if (msg.sender != _upgradeRightsOwner) {
            revert UUPSUpgradeableBase__Unauthorized();
        }
    }
}
