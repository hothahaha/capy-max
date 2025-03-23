// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISafe {
    function getOwners() external view returns (address[] memory);

    function getThreshold() external view returns (uint256);
}
