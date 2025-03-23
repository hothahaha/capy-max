// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title TestSafeUpgrade
 * @notice Script for testing Safe wallet multisig contract upgrade process on Anvil fork
 * @dev Uses real Safe wallet on Arbitrum One fork for testing
 */
contract TestSafeUpgrade is Script {
    address private safeWallet;
    // Replace these constants with your actual values
    address public STRATEGY_ENGINE_PROXY;

    uint256 public OWNER1_PRIVATE_KEY;
    uint256 public OWNER2_PRIVATE_KEY;

    // Safe transaction service API URL for Arbitrum
    string public constant SAFE_SERVICE_URL =
        "https://safe-transaction-arbitrum.safe.global/api/v1";

    function run() external {
        HelperConfig helperConfig = new HelperConfig();
        (, , , , , , safeWallet) = helperConfig.activeNetworkConfig();
        // Load private keys from environment
        OWNER1_PRIVATE_KEY = vm.envUint("OWNER1_PRIVATE_KEY");
        OWNER2_PRIVATE_KEY = vm.envUint("OWNER2_PRIVATE_KEY");

        console2.log("====== Safe Wallet Upgrade Test ======");
        console2.log("Safe wallet address: ", safeWallet);
        console2.log("Target contract proxy: ", STRATEGY_ENGINE_PROXY);
        console2.log("Owner 1 address: ", OWNER1_PRIVATE_KEY);
        console2.log("Owner 2 address: ", OWNER2_PRIVATE_KEY);

        // Step 1: Deploy new implementation contract using OWNER1_PRIVATE_KEY
        vm.startBroadcast(OWNER1_PRIVATE_KEY);

        StrategyEngine newImplementation = new StrategyEngine();

        vm.stopBroadcast();

        console2.log("\n[+] New implementation deployed at: ", address(newImplementation));

        // Step 2: Get current implementation for comparison
        address currentImpl;
        try StrategyEngine(STRATEGY_ENGINE_PROXY).implementation() returns (address impl) {
            currentImpl = impl;
        } catch {
            console2.log(
                "[!] Warning: Could not fetch current implementation - verify proxy address is correct"
            );
            currentImpl = address(0);
        }

        console2.log("[i] Current implementation: ", currentImpl);

        // Step 3: Generate upgrade transaction calldata
        bytes memory upgradeCalldata = abi.encodeWithSignature(
            "upgradeToAndCall(address,bytes)",
            address(newImplementation),
            "" // Empty bytes as we don't need to call a function
        );

        console2.log("\n====== Safe Transaction Details ======");
        console2.log("To: ", STRATEGY_ENGINE_PROXY);
        console2.log("Value: 0 ETH");
        console2.log("Data: ", _toHexString(upgradeCalldata));
        console2.log("Data length: ", upgradeCalldata.length, " bytes");

        // Step 4: Print Safe transaction creation instructions
        _printSafeInstructions(upgradeCalldata);

        // Step 5: (Optional) Simulate the transaction to verify it would succeed
        vm.startPrank(safeWallet);

        bool success;
        bytes memory returnData;
        (success, returnData) = STRATEGY_ENGINE_PROXY.call(upgradeCalldata);

        vm.stopPrank();

        console2.log("\n====== Transaction Simulation ======");
        console2.log("Simulation success: ", success);
        if (!success) {
            console2.log("Simulation reverted. Please check contract addresses and permissions.");
        } else {
            console2.log(
                "Simulation successful. Transaction should work when executed from Safe wallet."
            );
        }
    }

    function _printSafeInstructions(bytes memory upgradeCalldata) internal view {
        console2.log("\n====== How to Execute with Safe Wallet ======");
        console2.log("Option 1: Using Safe Web UI");
        console2.log("1. Go to https://app.safe.global");
        console2.log("2. Connect your wallet and select your Safe");
        console2.log("3. Create a new transaction with these parameters:");
        console2.log("   - To: ", STRATEGY_ENGINE_PROXY);
        console2.log("   - Value: 0");
        console2.log("   - Data: ", _toHexString(upgradeCalldata));
        console2.log("4. Sign with the first owner wallet");
        console2.log("5. Sign with the second owner wallet and execute");

        console2.log("\nOption 2: Using Safe Transaction Service API");
        console2.log("1. Create proposed transaction:");
        string memory createTxCmd = string(
            abi.encodePacked(
                "curl -X POST ",
                SAFE_SERVICE_URL,
                "/safes/",
                _addressToString(safeWallet),
                "/multisig-transactions/ ",
                "-H 'Content-Type: application/json' ",
                "-d '{",
                '"to": "',
                _addressToString(STRATEGY_ENGINE_PROXY),
                '",',
                '"value": "0",',
                '"data": "',
                _toHexString(upgradeCalldata),
                '",',
                '"nonce": null,',
                '"operation": 0,',
                '"safeTxGas": 0,',
                '"baseGas": 0,',
                '"gasPrice": 0,',
                '"gasToken": null,',
                '"refundReceiver": null,',
                '"contractTransactionHash": "...",',
                '"sender": "',
                _addressToString(vm.addr(OWNER1_PRIVATE_KEY)),
                '"',
                "}'"
            )
        );
        console2.log(createTxCmd);

        console2.log("\n2. Sign and confirm with remaining owners");
    }

    // Helper function to convert bytes to hex string
    function _toHexString(bytes memory data) internal pure returns (string memory) {
        bytes memory alphabet = "0123456789abcdef";
        bytes memory str = new bytes(2 + data.length * 2);
        str[0] = "0";
        str[1] = "x";
        for (uint256 i = 0; i < data.length; i++) {
            str[2 + i * 2] = alphabet[uint8(data[i] >> 4)];
            str[2 + 1 + i * 2] = alphabet[uint8(data[i] & 0x0f)];
        }
        return string(str);
    }

    // Helper function to convert address to string
    function _addressToString(address _addr) internal pure returns (string memory) {
        bytes memory s = new bytes(42);
        s[0] = "0";
        s[1] = "x";
        for (uint i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint(uint160(_addr)) / (2 ** (8 * (19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 + 2 * i] = _char(hi);
            s[2 + 2 * i + 1] = _char(lo);
        }
        return string(s);
    }

    function _char(bytes1 b) internal pure returns (bytes1) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }
}
