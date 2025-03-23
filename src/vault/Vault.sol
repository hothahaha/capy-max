// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeableBase} from "../upgradeable/UUPSUpgradeableBase.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

/// @title Vault
/// @notice Contract for storing and managing protocol profits
/// @dev Uses Safe wallet for access control and upgrades
contract Vault is Initializable, UUPSUpgradeableBase {
    using SafeERC20 for IERC20;

    // Errors
    error Vault__InvalidAmount();
    error Vault__InsufficientBalance();
    error Vault__TransferFailed();
    error Vault__Unauthorized();

    // Events
    event Deposit(address indexed token, uint256 amount);
    event Withdraw(address indexed token, uint256 amount);

    // State variables
    IERC20 public token;
    address public safeWallet;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    /// @notice Initialize the vault contract
    /// @param _token Address of the token to be managed
    /// @param _safeWallet Address of the Safe wallet for access control
    function initialize(address _token, address _safeWallet) public initializer {
        __UUPSUpgradeableBase_init(msg.sender);
        token = IERC20(_token);
        safeWallet = _safeWallet;
        transferUpgradeRights(_safeWallet);
    }

    /// @notice Deposit profits into the vault
    /// @param amount Amount of tokens to deposit
    function depositProfit(uint256 amount) external {
        if (amount == 0) revert Vault__InvalidAmount();
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(address(token), amount);
    }

    /// @notice Withdraw profits from the vault
    /// @dev Can only be called by the Safe wallet
    /// @param to Address to send the tokens to
    /// @param amount Amount of tokens to withdraw
    function withdrawProfit(address to, uint256 amount) external {
        if (amount == 0) revert Vault__InvalidAmount();
        if (msg.sender != safeWallet) revert Vault__Unauthorized();
        if (token.balanceOf(address(this)) < amount) revert Vault__InsufficientBalance();

        token.safeTransfer(to, amount);
        emit Withdraw(address(token), amount);
    }

    /// @notice Get the current token balance of the vault
    /// @return Current token balance
    function getBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
