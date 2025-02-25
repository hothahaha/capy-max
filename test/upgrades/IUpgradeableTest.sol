// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

abstract contract IUpgradeableTest {
    function getUpgradeableContract() public view virtual returns (address);

    function getNewImplementation() public virtual returns (address);

    function validateUpgrade() public virtual;
}
