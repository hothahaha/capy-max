// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract Vault is Ownable {
    using SafeERC20 for IERC20;

    error Vault__InvalidAmount();
    error Vault__TransferFailed();
    error Vault__Unauthorized();

    IERC20 public immutable token;
    mapping(address => bool) public authorized;

    event ProfitDeposited(uint256 amount);
    event ProfitWithdrawn(address indexed to, uint256 amount);
    event AuthorizationUpdated(address indexed user, bool status);

    constructor(address _token) Ownable(msg.sender) {
        token = IERC20(_token);
    }

    modifier onlyAuthorized() {
        if (!authorized[msg.sender] && msg.sender != owner()) {
            revert Vault__Unauthorized();
        }
        _;
    }

    function setAuthorization(address user, bool status) external onlyOwner {
        authorized[user] = status;
        emit AuthorizationUpdated(user, status);
    }

    function depositProfit(uint256 amount) external {
        if (amount == 0) revert Vault__InvalidAmount();
        token.safeTransferFrom(msg.sender, address(this), amount);
        emit ProfitDeposited(amount);
    }

    function withdrawProfit(
        address to,
        uint256 amount
    ) external onlyAuthorized {
        if (amount == 0) revert Vault__InvalidAmount();
        token.safeTransfer(to, amount);
        emit ProfitWithdrawn(to, amount);
    }
}
