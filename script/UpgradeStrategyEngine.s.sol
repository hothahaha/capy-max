// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {ISafe} from "../src/interfaces/safe/ISafe.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

/**
 * @title UpgradeStrategyEngine
 * @notice Script to upgrade StrategyEngine contract through Safe multisig
 * @dev This script will:
 * 1. Deploy new implementation
 * 2. Generate Safe transaction for upgrade
 * 3. Execute upgrade through Safe multisig
 */
contract UpgradeStrategyEngine is Script {
    // Constants
    address public constant PROXY_ADDRESS = address(0); // TODO: Replace with actual proxy address

    // State variables
    StrategyEngine public strategyEngine;
    ISafe public safe;
    address[] public safeOwners;
    HelperConfig public helperConfig;
    uint256 public safeThreshold;

    function run() public {
        // Get config
        helperConfig = new HelperConfig();
        (, , , , , uint256 deployerPrivateKey, address safeAddress) = helperConfig
            .activeNetworkConfig();

        // Initialize Safe contract and get threshold
        safe = ISafe(safeAddress);
        safeOwners = safe.getOwners();
        safeThreshold = safe.getThreshold();

        console2.log("Safe contract:", safeAddress);
        console2.log("Number of owners:", safeOwners.length);
        console2.log("Required signatures:", safeThreshold);

        vm.startBroadcast(deployerPrivateKey);

        // Deploy new implementation
        strategyEngine = new StrategyEngine();
        console2.log("New implementation deployed at:", address(strategyEngine));

        // Generate upgrade calldata
        bytes memory upgradeCalldata = abi.encodeCall(
            ITransparentUpgradeableProxy.upgradeToAndCall,
            (address(strategyEngine), "")
        );

        // Get Safe transaction hash
        uint256 nonce = safe.getNonce();
        bytes32 txHash = safe.getTransactionHash(
            PROXY_ADDRESS, // to
            0, // value
            upgradeCalldata, // data
            0, // operation (0 = call)
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            address(0), // refundReceiver
            nonce // nonce
        );

        console2.log("Safe transaction hash:", vm.toString(txHash));

        // Sign transaction with first owner
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, txHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Execute transaction through Safe
        // Note: This will only work if enough owners have signed
        try
            safe.execTransaction(
                PROXY_ADDRESS, // to
                0, // value
                upgradeCalldata, // data
                0, // operation
                0, // safeTxGas
                0, // baseGas
                0, // gasPrice
                address(0), // gasToken
                payable(address(0)), // refundReceiver
                signature // signatures
            )
        {
            console2.log("Upgrade executed successfully");
        } catch Error(string memory reason) {
            console2.log("Upgrade failed:", reason);
        }

        vm.stopBroadcast();

        // Print instructions for manual signing
        console2.log("\nTo complete the upgrade:");
        console2.log(
            "1. Additional owners need to sign the transaction with hash:",
            vm.toString(txHash)
        );
        console2.log("2. Once enough signatures are collected (threshold: %s):", safeThreshold);
        console2.log(
            "3. Execute the transaction through the Safe UI or directly through the contract"
        );
    }
}
