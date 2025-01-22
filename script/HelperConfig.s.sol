// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";
import {ERC20Mock} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/mocks/ERC20Mock.sol";
import {AaveV3ArbitrumAssets} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

contract HelperConfig is Script {
    // Struct
    struct NetworkConfig {
        address wbtc;
        address usdc;
        address cctp;
        uint256 deployerKey;
        bytes32 solanaAccount;
    }

    // Accounts
    uint256 public constant DEFAULT_ANVIL_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    bytes32 public constant SOLANA_ACCOUNT_ADDRESS =
        0x000000000000000000000000d0c31cb7d1e6988a9e373c37d8d8700453241f50;

    // Aave
    address public constant MAINNET_WBTC = AaveV3ArbitrumAssets.WBTC_UNDERLYING;
    address public constant MAINNET_USDC =
        AaveV3ArbitrumAssets.USDCn_UNDERLYING;
    address public constant TESTNET_USDC =
        0x75faf114eafb1BDbe2F0316DF893fd58CE46AA4d;

    // CCTP
    address public constant MAINNET_CCTP =
        0x19330d10D9Cc8751218eaf51E8885D058642E08A;
    address public constant TESTNET_CCTP =
        0x9f3B8679c73C2Fef8b59B4f3444d4e156fb70AA5;

    NetworkConfig public activeNetworkConfig;

    constructor() {
        if (block.chainid == 42161) {
            activeNetworkConfig = getArbitrumConfig();
        } else if (block.chainid == 421614) {
            activeNetworkConfig = getTestnetConfig();
        } else {
            activeNetworkConfig = getLocalConfig();
        }
    }

    function getLocalConfig() public pure returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_WBTC,
                usdc: MAINNET_USDC,
                cctp: MAINNET_CCTP,
                deployerKey: DEFAULT_ANVIL_KEY,
                solanaAccount: SOLANA_ACCOUNT_ADDRESS
            });
    }

    function getArbitrumConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_WBTC,
                usdc: MAINNET_USDC,
                cctp: MAINNET_CCTP,
                deployerKey: vm.envUint("PRIVATE_KEY"),
                solanaAccount: SOLANA_ACCOUNT_ADDRESS
            });
    }

    function getTestnetConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_WBTC,
                usdc: TESTNET_USDC,
                cctp: TESTNET_CCTP,
                deployerKey: vm.envUint("PRIVATE_KEY"),
                solanaAccount: SOLANA_ACCOUNT_ADDRESS
            });
    }
}
