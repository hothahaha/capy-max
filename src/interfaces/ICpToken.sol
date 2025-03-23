// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title ICpToken
 * @notice Interface for CpToken functionality
 */
interface ICpToken {
    /**
     * @notice Mints new tokens to the specified account
     * @param to The account to mint tokens to
     * @param amount The amount of tokens to mint
     */
    function mint(address to, uint256 amount) external;
}
