// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {MultiSig} from "../access/MultiSig.sol";

contract Vault is Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using SafeERC20 for IERC20;

    error Vault__InvalidAmount();
    error Vault__InsufficientBalance();
    error Vault__TransferFailed();
    error Vault__Unauthorized();

    IERC20 public token;
    MultiSig public multiSig;

    event Deposit(address indexed token, uint256 amount);
    event Withdraw(address indexed token, uint256 amount);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _token, address _multiSig) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        token = IERC20(_token);
        multiSig = MultiSig(_multiSig);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal override onlyOwner {}

    function depositProfit(uint256 amount) external {
        if (amount == 0) revert Vault__InvalidAmount();
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit Deposit(address(token), amount);
    }

    function withdrawProfit(address to, uint256 amount) external {
        if (amount == 0) revert Vault__InvalidAmount();
        if (msg.sender != address(multiSig)) revert Vault__Unauthorized();
        if (token.balanceOf(address(this)) < amount)
            revert Vault__InsufficientBalance();

        token.safeTransfer(to, amount);
        emit Withdraw(address(token), amount);
    }

    function getBalance() external view returns (uint256) {
        return token.balanceOf(address(this));
    }
}
