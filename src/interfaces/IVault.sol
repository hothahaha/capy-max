// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IVault
/// @notice Interface for the Vault contract that stores and manages protocol profits
interface IVault {
    // Events
    event Deposit(address indexed token, uint256 amount);
    event Withdraw(address indexed token, uint256 amount);

    // Functions
    function depositProfit(uint256 amount) external;

    function withdrawProfit(address to, uint256 amount) external;

    function getBalance() external view returns (uint256);
}
