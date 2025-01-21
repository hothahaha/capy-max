// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";

/// @title CpToken
/// @notice Non-transferable token representing user's deposit position
contract CpToken is
    Initializable,
    ERC20Upgradeable,
    OwnableUpgradeable,
    UUPSUpgradeable
{
    // Errors
    error CpToken__TransferNotAllowed();
    error CpToken__NotAuthorized();

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        string memory name,
        string memory symbol
    ) public initializer {
        __ERC20_init(name, symbol);
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    /// @notice Mint tokens to a user
    /// @param to The address to mint tokens to
    /// @param amount The amount of tokens to mint
    function mint(address to, uint256 amount) external onlyOwner {
        _mint(to, amount);
    }

    /// @notice Burn tokens from a user
    /// @param from The address to burn tokens from
    /// @param amount The amount of tokens to burn
    function burn(address from, uint256 amount) external onlyOwner {
        _burn(from, amount);
    }

    /// @notice Override transfer to prevent token transfers
    function transfer(address, uint256) public pure override returns (bool) {
        revert CpToken__TransferNotAllowed();
    }

    /// @notice Override transferFrom to prevent token transfers
    function transferFrom(
        address,
        address,
        uint256
    ) public pure override returns (bool) {
        revert CpToken__TransferNotAllowed();
    }

    /// @notice Override approve to prevent approvals
    function approve(address, uint256) public pure override returns (bool) {
        revert CpToken__TransferNotAllowed();
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}
}
