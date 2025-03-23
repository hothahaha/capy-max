// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {Vault} from "../src/vault/Vault.sol";
import {IStrategyEngine} from "../src/interfaces/IStrategyEngine.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/// @title DeployScript
/// @notice Script for deploying the protocol contracts
/// @dev Uses Safe wallet for protocol governance
contract DeployScript is Script {
    struct DeployConfig {
        address wbtcAddress;
        address usdcAddress;
        address aavePool;
        address aaveOracle;
        address aaveProtocolDataProvider;
        uint256 deployerKey;
        address safe;
    }

    function run()
        public
        returns (StrategyEngine engine, CpToken cpToken, Vault vault, HelperConfig helperConfig)
    {
        helperConfig = new HelperConfig();
        DeployConfig memory config = _loadConfig(helperConfig);
        address initialDeployer = vm.addr(config.deployerKey);

        vm.startBroadcast(config.deployerKey);

        // Deploy contracts
        cpToken = deployCpToken(initialDeployer, config.safe);
        vault = deployVault(config.usdcAddress, config.safe);
        engine = deployStrategyEngine(config, address(cpToken), address(vault));

        // Transfer ownerships to the engine
        cpToken.transferOwnership(address(engine));
        vault.transferOwnership(address(engine));

        vm.stopBroadcast();
    }

    function _loadConfig(
        HelperConfig helperConfig
    ) internal view returns (DeployConfig memory config) {
        (
            config.wbtcAddress,
            config.usdcAddress,
            config.aavePool,
            config.aaveOracle,
            config.aaveProtocolDataProvider,
            config.deployerKey,
            config.safe
        ) = helperConfig.activeNetworkConfig();
    }

    /// @notice Deploy CpToken contract
    /// @param initialDeployer Initial deployer address
    /// @param safeWallet Safe wallet address for governance
    /// @return cpToken The deployed CpToken contract
    function deployCpToken(address initialDeployer, address safeWallet) internal returns (CpToken) {
        CpToken cpTokenImpl = new CpToken();
        ERC1967Proxy cpTokenProxy = new ERC1967Proxy(address(cpTokenImpl), "");
        CpToken(address(cpTokenProxy)).initialize(
            initialDeployer,
            "Compound BTC",
            "cpBTC",
            safeWallet
        );
        return CpToken(address(cpTokenProxy));
    }

    /// @notice Deploy Vault contract
    /// @param usdc USDC token address
    /// @param safeWallet Safe wallet address for governance
    /// @return vault The deployed Vault contract
    function deployVault(address usdc, address safeWallet) internal returns (Vault) {
        Vault vaultImpl = new Vault();
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), "");
        Vault(address(vaultProxy)).initialize(usdc, safeWallet);
        return Vault(address(vaultProxy));
    }

    /// @notice Deploy StrategyEngine contract
    /// @param config Deployment configuration
    /// @param cpToken CpToken contract address
    /// @param vault Vault contract address
    /// @return engine The deployed StrategyEngine contract
    function deployStrategyEngine(
        DeployConfig memory config,
        address cpToken,
        address vault
    ) internal returns (StrategyEngine) {
        StrategyEngine engineImpl = new StrategyEngine();
        ERC1967Proxy engineProxy = new ERC1967Proxy(address(engineImpl), "");

        StrategyEngine.EngineInitParams memory params = IStrategyEngine.EngineInitParams({
            wbtc: config.wbtcAddress,
            usdc: config.usdcAddress,
            aavePool: config.aavePool,
            aaveOracle: config.aaveOracle,
            aaveProtocolDataProvider: config.aaveProtocolDataProvider,
            cpToken: cpToken,
            vault: vault,
            safeWallet: config.safe
        });

        StrategyEngine(address(engineProxy)).initialize(params);

        return StrategyEngine(address(engineProxy));
    }
}
