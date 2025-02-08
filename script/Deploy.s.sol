// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {Vault} from "../src/vault/Vault.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
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
        (
            address wbtcAddress,
            address usdcAddress,
            uint256 deployerKey
        ) = helperConfig.activeNetworkConfig();

        vm.startBroadcast(deployerKey);
        address initialSigner = vm.addr(deployerKey);

        // 部署合约
        signerManager = deploySignerManager(initialSigner);
        multiSig = deployMultiSig(address(signerManager));
        signerManager.setMultiSig(address(multiSig));

        cpToken = deployCpToken();
        vault = deployVault(usdcAddress, address(multiSig));
        engine = deployStrategyEngine(
            wbtcAddress,
            usdcAddress,
            address(cpToken),
            address(vault),
            address(signerManager)
        );

        // 设置所有权
        vault.transferUpgradeRights(address(multiSig));
        engine.transferUpgradeRights(address(multiSig));

        // 将 SignerManager 的所有权转移给 engine
        cpToken.transferOwnership(address(engine));
        signerManager.transferOwnership(address(engine));

        vm.stopBroadcast();
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

    function deployMultiSig(address signerManager) internal returns (MultiSig) {
        MultiSig multiSigImpl = new MultiSig();
        ERC1967Proxy multiSigProxy = new ERC1967Proxy(
            address(multiSigImpl),
            ""
        );
        MultiSig(address(multiSigProxy)).initialize(signerManager);
        return MultiSig(address(multiSigProxy));
    }

    function deployCpToken() internal returns (CpToken) {
        CpToken cpTokenImpl = new CpToken();
        ERC1967Proxy cpTokenProxy = new ERC1967Proxy(address(cpTokenImpl), "");
        CpToken(address(cpTokenProxy)).initialize("Compound BTC", "cpBTC");
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
        address wbtc,
        address usdc,
        address cpToken,
        address vault,
        address signerManager
    ) internal returns (StrategyEngine) {
        // Deploy StrategyEngine implementation and proxy
        StrategyEngine engineImpl = new StrategyEngine();
        ERC1967Proxy engineProxy = new ERC1967Proxy(address(engineImpl), "");

        StrategyEngine(address(engineProxy)).initialize(
            wbtc,
            usdc,
            cpToken,
            vault,
            signerManager
        );

        return StrategyEngine(address(engineProxy));
    }
}
