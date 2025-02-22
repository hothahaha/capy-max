// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from 'forge-std/Script.sol';
import {IERC20} from '@openzeppelin/contracts/token/ERC20/IERC20.sol';
import {ITokenMessenger} from '../src/cctp/interface/ITokenMessenger.sol';
import {HelperConfig} from './HelperConfig.s.sol';

contract BridgeScript is Script {
  // Constants
  uint32 constant SOLANA_DOMAIN = 5;
  uint256 constant AMOUNT = 1e6; // 1 USDC (6 decimals)
  bytes32 constant SOLANA_RECIPIENT =
    // 0x000000000000000000000000e8c5b8ad76e4ada0fd54978520520df5cd461c52;
    0x2add88b3ed0489995dce4a09f6c4da9f27a54d45b58bff52de24ee5414e02d3b;
  address constant USDC = 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d;

  function run() external {
    // Get deployer private key
    HelperConfig helperConfig = new HelperConfig();
    (, , , , , uint256 deployerKey, address tokenMessenger, ) = helperConfig
      .activeNetworkConfig();

    vm.startBroadcast(deployerKey);

    // Approve TokenMessenger to use USDC
    IERC20(USDC).approve(tokenMessenger, AMOUNT);

    // 执行跨链传输
    ITokenMessenger(tokenMessenger).depositForBurn(
      AMOUNT,
      SOLANA_DOMAIN,
      SOLANA_RECIPIENT,
      USDC
    );

    vm.stopBroadcast();
  }
}
