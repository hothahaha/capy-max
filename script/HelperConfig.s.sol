// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {MockERC20} from "../src/erc20/MockERC20.sol";
import {Script, console2} from "forge-std/Script.sol";
import {ERC20Mock} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/mocks/ERC20Mock.sol";
import {AaveV3ArbitrumAssets} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";

contract HelperConfig is Script {
    // Struct
    struct NetworkConfig {
        address wbtc;
        address usdc;
        address wormholeCCTP;
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

    // Wormhole
    address public constant WORMHOLE_CCTP =
        0x2703483B1a5a7c577e8680de9Df8Be03c6f30e3c;

    NetworkConfig public activeNetworkConfig;

    constructor() {
        // if (block.chainid == 42161) {
        //     activeNetworkConfig = getArbitrumConfig();
        // } else {
        activeNetworkConfig = getLocalConfig();
        // }
    }

    function getLocalConfig() public pure returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_WBTC,
                usdc: MAINNET_USDC,
                wormholeCCTP: WORMHOLE_CCTP,
                deployerKey: DEFAULT_ANVIL_KEY,
                solanaAccount: SOLANA_ACCOUNT_ADDRESS
            });
    }

    function getArbitrumConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_WBTC,
                usdc: MAINNET_USDC,
                wormholeCCTP: WORMHOLE_CCTP,
                deployerKey: vm.envUint("PRIVATE_KEY"),
                solanaAccount: SOLANA_ACCOUNT_ADDRESS
            });
    }
}
