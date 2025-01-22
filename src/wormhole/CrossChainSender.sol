// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITokenMessenger} from "../cctp/interface/ITokenMessenger.sol";

contract CrossChainSender {
    // 状态变量
    IERC20 public immutable usdc;
    ITokenMessenger public immutable cctp;
    bytes32 public immutable solanaAccount;
    uint32 public constant DESTINATION_DOMAIN = 5;

    // 事件
    event CrossChainDeposited(
        address indexed sender,
        uint256 amount,
        bytes32 recipient
    );

    // 错误
    error CrossChainSender__InsufficientAllowance();
    error CrossChainSender__TransferFailed();

    constructor(address _usdc, address _cctp, bytes32 _solanaAccount) {
        usdc = IERC20(_usdc);
        cctp = ITokenMessenger(_cctp);
        solanaAccount = _solanaAccount;
    }

    function deposit(uint256 amount) external {
        // 检查授权
        if (usdc.allowance(msg.sender, address(this)) < amount) {
            revert CrossChainSender__InsufficientAllowance();
        }

        // 转移 USDC 到合约
        bool success = usdc.transferFrom(msg.sender, address(this), amount);
        if (!success) {
            revert CrossChainSender__TransferFailed();
        }

        // 授权 CCTP 使用 USDC
        usdc.approve(address(cctp), amount);

        // 调用 CCTP 进行跨链传输
        cctp.depositForBurn(
            amount,
            DESTINATION_DOMAIN,
            solanaAccount,
            address(usdc)
        );

        emit CrossChainDeposited(msg.sender, amount, solanaAccount);
    }
}
