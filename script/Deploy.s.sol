// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {Vault} from "../src/vault/Vault.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {IStrategyEngine} from "../src/interfaces/IStrategyEngine.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    struct DeployConfig {
        address wbtcAddress;
        address usdcAddress;
        address aavePool;
        address aaveOracle;
        address aaveProtocolDataProvider;
        uint256 deployerKey;
        address tokenMessenger;
        bytes32 solanaAddress;
    }

    function run()
        public
        returns (
            StrategyEngine engine,
            CpToken cpToken,
            Vault vault,
            SignerManager signerManager,
            MultiSig multiSig,
            HelperConfig helperConfig
        )
    {
        helperConfig = new HelperConfig();
        DeployConfig memory config = _loadConfig(helperConfig);
        address initialSigner = vm.addr(config.deployerKey);

        vm.startBroadcast(config.deployerKey);

        // 部署合约
        signerManager = deploySignerManager(initialSigner);
        multiSig = deployMultiSig(initialSigner, address(signerManager));
        signerManager.setMultiSig(address(multiSig));

        cpToken = deployCpToken(initialSigner);
        vault = deployVault(config.usdcAddress, address(multiSig));
        engine = deployStrategyEngine(
            config,
            address(cpToken),
            address(vault),
            address(signerManager)
        );

        _setupUpgradeRights(engine, cpToken, vault, signerManager, multiSig);
        _transferOwnerships(engine, cpToken, vault, signerManager);

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
            config.tokenMessenger,
            config.solanaAddress
        ) = helperConfig.activeNetworkConfig();
    }

    function _setupUpgradeRights(
        StrategyEngine engine,
        CpToken cpToken,
        Vault vault,
        SignerManager signerManager,
        MultiSig multiSig
    ) internal {
        multiSig.transferUpgradeRights(address(multiSig));
        signerManager.transferUpgradeRights(address(multiSig));
        vault.transferUpgradeRights(address(multiSig));
        cpToken.transferUpgradeRights(address(multiSig));
        engine.transferUpgradeRights(address(multiSig));
    }

    function _transferOwnerships(
        StrategyEngine engine,
        CpToken cpToken,
        Vault vault,
        SignerManager signerManager
    ) internal {
        cpToken.transferOwnership(address(engine));
        vault.transferOwnership(address(engine));
        signerManager.transferOwnership(address(engine));
    }

    function deploySignerManager(
        address initialSigner
    ) internal returns (SignerManager) {
        SignerManager signerManagerImpl = new SignerManager();
        ERC1967Proxy signerManagerProxy = new ERC1967Proxy(
            address(signerManagerImpl),
            ""
        );
        SignerManager manager = SignerManager(address(signerManagerProxy));
        manager.initialize(initialSigner, 1);
        return manager;
    }

    function deployMultiSig(
        address initialSigner,
        address signerManager
    ) internal returns (MultiSig) {
        MultiSig multiSigImpl = new MultiSig();
        ERC1967Proxy multiSigProxy = new ERC1967Proxy(
            address(multiSigImpl),
            ""
        );
        MultiSig(address(multiSigProxy)).initialize(
            initialSigner,
            signerManager
        );
        return MultiSig(address(multiSigProxy));
    }

    function deployCpToken(address initialSigner) internal returns (CpToken) {
        CpToken cpTokenImpl = new CpToken();
        ERC1967Proxy cpTokenProxy = new ERC1967Proxy(address(cpTokenImpl), "");
        CpToken(address(cpTokenProxy)).initialize(
            initialSigner,
            "Compound BTC",
            "cpBTC"
        );
        return CpToken(address(cpTokenProxy));
    }

    function deployVault(
        address usdc,
        address multiSig
    ) internal returns (Vault) {
        Vault vaultImpl = new Vault();
        ERC1967Proxy vaultProxy = new ERC1967Proxy(address(vaultImpl), "");
        Vault(address(vaultProxy)).initialize(usdc, multiSig);
        return Vault(address(vaultProxy));
    }

    function deployStrategyEngine(
        DeployConfig memory config,
        address cpToken,
        address vault,
        address signerManager
    ) internal returns (StrategyEngine) {
        StrategyEngine engineImpl = new StrategyEngine();
        ERC1967Proxy engineProxy = new ERC1967Proxy(address(engineImpl), "");

        StrategyEngine.EngineInitParams memory params = IStrategyEngine
            .EngineInitParams({
                wbtc: config.wbtcAddress,
                usdc: config.usdcAddress,
                aavePool: config.aavePool,
                aaveOracle: config.aaveOracle,
                aaveProtocolDataProvider: config.aaveProtocolDataProvider,
                cpToken: cpToken,
                vault: vault,
                signerManager: signerManager,
                tokenMessenger: config.tokenMessenger,
                solanaAddress: config.solanaAddress
            });

        StrategyEngine(address(engineProxy)).initialize(params);

        return StrategyEngine(address(engineProxy));
    }
}
