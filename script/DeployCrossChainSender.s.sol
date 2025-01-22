// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {CrossChainSender} from "../src/wormhole/CrossChainSender.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

contract DeployCrossChainSender is Script {
    function run() external returns (CrossChainSender) {
        HelperConfig config = new HelperConfig();
        (
            ,
            address usdc,
            address cctp,
            uint256 deployerKey,
            bytes32 solanaAccount
        ) = config.activeNetworkConfig();

        vm.startBroadcast(deployerKey);

        CrossChainSender crossChainSender = new CrossChainSender(
            usdc,
            cctp,
            solanaAccount
        );

        vm.stopBroadcast();

        return crossChainSender;
    }
}
