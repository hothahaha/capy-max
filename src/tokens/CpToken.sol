// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20Upgradeable} from "@openzeppelin/contracts-upgradeable/token/ERC20/ERC20Upgradeable.sol";
import {UUPSUpgradeableBase} from "../upgradeable/UUPSUpgradeableBase.sol";
import {MultiSig} from "../access/MultiSig.sol";

/// @title CpToken
/// @notice Non-transferable token representing user's deposit position
contract CpToken is ERC20Upgradeable, UUPSUpgradeableBase {
    // Errors
    error CpToken__Unauthorized();
    error CpToken__InvalidAmount();
    error CpToken__TransferNotAllowed();

    MultiSig public multiSig;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(
        address initialOwner,
        string memory name,
        string memory symbol,
        address _multiSig
    ) external initializer {
        __UUPSUpgradeableBase_init(initialOwner);
        __ERC20_init(name, symbol);
        multiSig = MultiSig(_multiSig);
        transferUpgradeRights(address(multiSig));
    }

    /// @notice Mint tokens to a user
    /// @param to The address to mint tokens to
    /// @param amount The amount of tokens to mint
    function mint(address to, uint256 amount) external onlyOwner {
        if (amount == 0) revert CpToken__InvalidAmount();
        _mint(to, amount);
    }

    /// @notice Burn tokens from a user
    /// @param from The address to burn tokens from
    /// @param amount The amount of tokens to burn
    function burn(address from, uint256 amount) external onlyOwner {
        if (amount == 0) revert CpToken__InvalidAmount();
        _burn(from, amount);
    }

    /// @notice Override transfer to prevent token transfers
    function transfer(address, uint256) public pure override returns (bool) {
        revert CpToken__TransferNotAllowed();
    }

    /// @notice Override transferFrom to prevent token transfers
    function transferFrom(address, address, uint256) public pure override returns (bool) {
        revert CpToken__TransferNotAllowed();
    }

    /// @notice Override approve to prevent approvals
    function approve(address, uint256) public pure override returns (bool) {
        revert CpToken__TransferNotAllowed();
    }
}
