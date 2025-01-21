// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {HelperConfig} from "./HelperConfig.s.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function run() external returns (StrategyEngine, CpToken, HelperConfig) {
        HelperConfig config = new HelperConfig();
        (
            address wbtc,
            address usdc,
            address wormholeCCTP,
            uint256 deployerKey,
            bytes32 solanaAccount
        ) = config.activeNetworkConfig();

        vm.startBroadcast(deployerKey);

        // Deploy CpToken implementation and proxy
        CpToken cpTokenImpl = new CpToken();
        ERC1967Proxy cpTokenProxy = new ERC1967Proxy(
            address(cpTokenImpl),
            abi.encodeWithSelector(
                CpToken.initialize.selector,
                "Compound BTC",
                "cpBTC"
            )
        );
        CpToken cpToken = CpToken(address(cpTokenProxy));

        // Deploy StrategyEngine implementation and proxy
        StrategyEngine engineImpl = new StrategyEngine();
        ERC1967Proxy engineProxy = new ERC1967Proxy(
            address(engineImpl),
            abi.encodeWithSelector(
                StrategyEngine.initialize.selector,
                wbtc,
                usdc,
                address(cpToken),
                wormholeCCTP,
                solanaAccount
            )
        );
        StrategyEngine engine = StrategyEngine(address(engineProxy));

        // Transfer ownership of CpToken to StrategyEngine
        cpToken.transferOwnership(address(engine));

        vm.stopBroadcast();
        return (engine, cpToken, config);
    }
}
