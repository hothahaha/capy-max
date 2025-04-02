// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script, console2} from "forge-std/Script.sol";

import {ERC20Mock} from "@chainlink/contracts/src/v0.8/vendor/openzeppelin-solidity/v4.8.3/contracts/mocks/ERC20Mock.sol";
import {AaveV3ArbitrumAssets, AaveV3Arbitrum} from "@bgd-labs/aave-address-book/AaveV3Arbitrum.sol";
import {AaveV3ArbitrumSepoliaAssets, AaveV3ArbitrumSepolia} from "@bgd-labs/aave-address-book/AaveV3ArbitrumSepolia.sol";
import {AaveV3SepoliaAssets, AaveV3Sepolia} from "@bgd-labs/aave-address-book/AaveV3Sepolia.sol";

contract HelperConfig is Script {
    // Struct
    struct NetworkConfig {
        address wbtc;
        address usdc;
        address aavePool;
        address aaveOracle;
        address aaveProtocolDataProvider;
        uint256 deployerKey;
        address safe;
    }

    // Accounts
    uint256 public constant DEFAULT_ANVIL_KEY =
        0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
    bytes32 public constant SOLANA_ACCOUNT_ADDRESS =
        0x000000000000000000000000d0c31cb7d1e6988a9e373c37d8d8700453241f50;

    // Aave Arbitrum Mainnet
    address public constant MAINNET_AAVE_V3_ARBITRUM_POOL = address(AaveV3Arbitrum.POOL);
    address public constant MAINNET_AAVE_V3_ARBITRUM_ORACLE = address(AaveV3Arbitrum.ORACLE);
    address public constant MAINNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER =
        address(AaveV3Arbitrum.AAVE_PROTOCOL_DATA_PROVIDER);

    address public constant MAINNET_AAVE_V3_ARBITRUM_WBTC = AaveV3ArbitrumAssets.WBTC_UNDERLYING;
    address public constant MAINNET_AAVE_V3_ARBITRUM_USDC = AaveV3ArbitrumAssets.USDCn_UNDERLYING;

    // Aave Arbitrum Testnet
    address public constant TESTNET_AAVE_V3_ARBITRUM_POOL = address(AaveV3ArbitrumSepolia.POOL);
    address public constant TESTNET_AAVE_V3_ARBITRUM_ORACLE = address(AaveV3ArbitrumSepolia.ORACLE);
    address public constant TESTNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER =
        address(AaveV3ArbitrumSepolia.AAVE_PROTOCOL_DATA_PROVIDER);

    address public constant TESTNET_AAVE_V3_ARBITRUM_WBTC = address(0);
    address public constant TESTNET_AAVE_V3_ARBITRUM_USDC =
        AaveV3ArbitrumSepoliaAssets.USDC_UNDERLYING;

    // Aave Sepolia Testnet
    address public constant TESTNET_AAVE_V3_SEPOLIA_POOL = address(AaveV3Sepolia.POOL);
    address public constant TESTNET_AAVE_V3_SEPOLIA_ORACLE = address(AaveV3Sepolia.ORACLE);
    address public constant TESTNET_AAVE_V3_SEPOLIA_PROTOCOL_DATA_PROVIDER =
        address(AaveV3Sepolia.AAVE_PROTOCOL_DATA_PROVIDER);

    address public constant TESTNET_AAVE_V3_SEPOLIA_WBTC = AaveV3SepoliaAssets.WBTC_UNDERLYING;
    address public constant TESTNET_AAVE_V3_SEPOLIA_USDC =
        0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238;

    // Safe
    address public constant ARBITRUM_SAFE = 0xC05e565c0BD64C95C0Bc4891FC5A3735fe5b139e;
    address public constant ARBITRUM_SEPOLIA_SAFE = 0x41675C099F32341bf84BFc5382aF534df5C7461a;
    address public constant SEPOLIA_SAFE = 0xC05e565c0BD64C95C0Bc4891FC5A3735fe5b139e;

    NetworkConfig public activeNetworkConfig;

    constructor() {
        if (block.chainid == 42161) {
            activeNetworkConfig = getArbitrumConfig();
        } else if (block.chainid == 421614) {
            activeNetworkConfig = getArbitrumTestnetConfig();
        } else if (block.chainid == 11155111) {
            activeNetworkConfig = getSepoliaConfig();
        } else {
            activeNetworkConfig = getLocalConfig();
        }
    }

    function getLocalConfig() public pure returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_AAVE_V3_ARBITRUM_WBTC,
                usdc: MAINNET_AAVE_V3_ARBITRUM_USDC,
                aavePool: MAINNET_AAVE_V3_ARBITRUM_POOL,
                aaveOracle: MAINNET_AAVE_V3_ARBITRUM_ORACLE,
                aaveProtocolDataProvider: MAINNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER,
                deployerKey: DEFAULT_ANVIL_KEY,
                safe: ARBITRUM_SAFE
            });
    }

    function getArbitrumConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: MAINNET_AAVE_V3_ARBITRUM_WBTC,
                usdc: MAINNET_AAVE_V3_ARBITRUM_USDC,
                aavePool: MAINNET_AAVE_V3_ARBITRUM_POOL,
                aaveOracle: MAINNET_AAVE_V3_ARBITRUM_ORACLE,
                aaveProtocolDataProvider: MAINNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER,
                deployerKey: vm.envUint("MAINNET_PRIVATE_KEY"),
                safe: ARBITRUM_SAFE
            });
    }

    function getSepoliaConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: TESTNET_AAVE_V3_SEPOLIA_WBTC,
                usdc: TESTNET_AAVE_V3_SEPOLIA_USDC,
                aavePool: TESTNET_AAVE_V3_SEPOLIA_POOL,
                aaveOracle: TESTNET_AAVE_V3_SEPOLIA_ORACLE,
                aaveProtocolDataProvider: TESTNET_AAVE_V3_SEPOLIA_PROTOCOL_DATA_PROVIDER,
                deployerKey: vm.envUint("TESTNET_PRIVATE_KEY"),
                safe: SEPOLIA_SAFE
            });
    }

    function getArbitrumTestnetConfig() public view returns (NetworkConfig memory) {
        return
            NetworkConfig({
                wbtc: TESTNET_AAVE_V3_ARBITRUM_WBTC,
                usdc: TESTNET_AAVE_V3_ARBITRUM_USDC,
                aavePool: TESTNET_AAVE_V3_ARBITRUM_POOL,
                aaveOracle: TESTNET_AAVE_V3_ARBITRUM_ORACLE,
                aaveProtocolDataProvider: TESTNET_AAVE_V3_ARBITRUM_PROTOCOL_DATA_PROVIDER,
                deployerKey: vm.envUint("TESTNET_PRIVATE_KEY"),
                safe: ARBITRUM_SEPOLIA_SAFE
            });
    }
}
