// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {ERC20Mock} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/mocks/ERC20Mock.sol";
import {AaveV3ArbitrumAssets, AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";
import {AaveV3ArbitrumSepoliaAssets, AaveV3ArbitrumSepolia} from "@bgd-labs/aave-address-book/AaveV3ArbitrumSepolia.sol";

contract HelperConfig is Script {
    // Struct
    struct NetworkConfig {
        address wbtc;
        address usdc;
        address aavePool;
        address aaveOracle;
        address aaveProtocolDataProvider;
        uint256 deployerKey;
        address tokenMessenger;
        bytes32 solanaAddress;
    }

    // Accounts
    uint256 public constant DEFAULT_ANVIL_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    bytes32 public constant SOLANA_ACCOUNT_ADDRESS =
        0x000000000000000000000000d0c31cb7d1e6988a9e373c37d8d8700453241f50;

    // Aave Mainnet
    address public constant MAINNET_AAVE_V3_ARBITRUM_POOL =
        address(AaveV3Arbitrum.POOL);
    address public constant MAINNET_AAVE_V3_ARBITRUM_ORACLE =
        address(AaveV3Arbitrum.ORACLE);
    address public constant MAINNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER =
        address(AaveV3Arbitrum.AAVE_PROTOCOL_DATA_PROVIDER);

    address public constant MAINNET_WBTC = AaveV3ArbitrumAssets.WBTC_UNDERLYING;
    address public constant MAINNET_USDC =
        AaveV3ArbitrumAssets.USDCn_UNDERLYING;

    // Aave Testnet
    address public constant TESTNET_AAVE_V3_ARBITRUM_POOL =
        address(AaveV3ArbitrumSepolia.POOL);
    address public constant TESTNET_AAVE_V3_ARBITRUM_ORACLE =
        address(AaveV3ArbitrumSepolia.ORACLE);
    address public constant TESTNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER =
        address(AaveV3ArbitrumSepolia.AAVE_PROTOCOL_DATA_PROVIDER);

    address public constant TESTNET_WBTC = address(0);
    address public constant TESTNET_USDC =
        AaveV3ArbitrumSepoliaAssets.USDC_UNDERLYING;

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
                aavePool: MAINNET_AAVE_V3_ARBITRUM_POOL,
                aaveOracle: MAINNET_AAVE_V3_ARBITRUM_ORACLE,
                aaveProtocolDataProvider: MAINNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER,
                deployerKey: DEFAULT_ANVIL_KEY,
                tokenMessenger: MAINNET_CCTP_TOKEN_MESSENGER,
                solanaAddress: MAINNET_SOLANA_ADDRESS
            });
    }

    function getArbitrumConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_WBTC,
                usdc: MAINNET_USDC,
                aavePool: MAINNET_AAVE_V3_ARBITRUM_POOL,
                aaveOracle: MAINNET_AAVE_V3_ARBITRUM_ORACLE,
                aaveProtocolDataProvider: MAINNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER,
                deployerKey: vm.envUint("PRIVATE_KEY"),
                tokenMessenger: MAINNET_CCTP_TOKEN_MESSENGER,
                solanaAddress: MAINNET_SOLANA_ADDRESS
            });
    }

    function getTestnetConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: TESTNET_WBTC,
                usdc: TESTNET_USDC,
                aavePool: TESTNET_AAVE_V3_ARBITRUM_POOL,
                aaveOracle: TESTNET_AAVE_V3_ARBITRUM_ORACLE,
                aaveProtocolDataProvider: TESTNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER,
                deployerKey: vm.envUint("PRIVATE_KEY"),
                tokenMessenger: TESTNET_CCTP_TOKEN_MESSENGER,
                solanaAddress: TESTNET_SOLANA_ADDRESS
            });
    }
}
