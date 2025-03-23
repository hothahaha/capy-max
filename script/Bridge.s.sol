// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ITokenMessenger} from "../src/interfaces/cctp/ITokenMessenger.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract BridgeScript is Script {
    // Constants
    uint32 constant SOLANA_DOMAIN = 5;
    uint256 constant AMOUNT = 1e6; // 1 USDC (6 decimals)
    // CCTP
    address public constant MAINNET_CCTP_TOKEN_MESSENGER =
        0x19330d10D9Cc8751218eaf51E8885D058642E08A;
    address public constant TESTNET_CCTP_TOKEN_MESSENGER =
        0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5;

    // SOLANA ADDRESS
    bytes32 public constant MAINNET_SOLANA_ADDRESS =
        0x64e3f8485b44fd8f0a3d1a4b1e7d2e5e24f9c392fd482457cd3e66eec1fa6ad9;
    bytes32 public constant TESTNET_SOLANA_ADDRESS =
        0x64e3f8485b44fd8f0a3d1a4b1e7d2e5e24f9c392fd482457cd3e66eec1fa6ad9;

    bytes32 constant SOLANA_RECIPIENT =
        // 0x000000000000000000000000e8c5b8ad76e4ada0fd54978520520df5cd461c52;
        0xc2a8f9a5bb13c99d045dfac81cdccd78d51e2ff81eb9339ba1b7493f170710f1;
    // address constant USDC = 0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d; // Sepolia
    address constant USDC = 0xaf88d065e77c8cC2239327C5EDb3A432268e5831; // Mainnet

    function run() external {
        // Get deployer private key
        HelperConfig helperConfig = new HelperConfig();
        (, , , , , uint256 deployerKey, ) = helperConfig.activeNetworkConfig();

        vm.startBroadcast(deployerKey);

        // Approve TokenMessenger to use USDC
        IERC20(USDC).approve(MAINNET_CCTP_TOKEN_MESSENGER, AMOUNT);

        // 执行跨链传输
        ITokenMessenger(MAINNET_CCTP_TOKEN_MESSENGER).depositForBurn(
            AMOUNT,
            SOLANA_DOMAIN,
            SOLANA_RECIPIENT,
            USDC
        );

        vm.stopBroadcast();
    }
}
