// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

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

    function __UUPSUpgradeableBase_init(address initialOwner) internal onlyInitializing {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
        _upgradeRightsOwner = initialOwner;
    }

    /// @notice Transfer upgrade rights
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
    function upgradeRightsOwner() public view returns (address) {
        return _upgradeRightsOwner;
    }

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
