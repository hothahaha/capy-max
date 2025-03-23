// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import {console2} from "forge-std/console2.sol";
import {Vault} from "../src/vault/Vault.sol";
import {HelperConfig} from "./HelperConfig.s.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/**
 * @title TestVaultWithdrawal
 * @notice Script for testing Vault withdrawProfit function with Safe wallet multisig
 * @dev Uses real Safe wallet on Arbitrum One fork for testing
 */
contract TestVaultWithdrawal is Script {
    // Safe configuration from environment
    address private usdc;
    address private safeWallet;
    address public vaultProxyAddress;
    uint256 public OWNER1_PRIVATE_KEY;
    uint256 public OWNER2_PRIVATE_KEY;

    // Withdrawal parameters - adjust as needed
    address public constant RECIPIENT = 0xBdd427CFFA233858024B1D74220A9669918dC8a2; // Default to env SENDER
    uint256 public constant WITHDRAW_AMOUNT = 1e18; // 1 token with 18 decimals

    // Safe transaction service API URL for Arbitrum
    string public constant SAFE_SERVICE_URL =
        "https://safe-transaction-arbitrum.safe.global/api/v1";

    function run() external {
        // Load private keys from environment
        OWNER1_PRIVATE_KEY = vm.envUint("OWNER1_PRIVATE_KEY");
        OWNER2_PRIVATE_KEY = vm.envUint("OWNER2_PRIVATE_KEY");

        // Load configuration
        HelperConfig helperConfig = new HelperConfig();
        (, usdc, , , , , safeWallet) = helperConfig.activeNetworkConfig();

        // You need to set your Vault proxy address here or load from environment
        vaultProxyAddress = vm.envAddress("VAULT_PROXY"); // Load from .env or replace with actual address

        // Get owner addresses from private keys
        address owner1 = vm.addr(OWNER1_PRIVATE_KEY);
        address owner2 = vm.addr(OWNER2_PRIVATE_KEY);

        console2.log("====== Vault Withdraw Test ======");
        console2.log("Safe wallet address: ", safeWallet);
        console2.log("Vault contract: ", vaultProxyAddress);
        console2.log("Owner 1 address: ", owner1);
        console2.log("Owner 2 address: ", owner2);

        // Get current vault balance for reference
        Vault vault = Vault(vaultProxyAddress);
        uint256 currentBalance;
        try vault.getBalance() returns (uint256 balance) {
            currentBalance = balance;
            console2.log("\nCurrent vault balance: ", currentBalance);
        } catch {
            console2.log(
                "\n[!] Warning: Could not fetch vault balance - verify vault address is correct"
            );
            currentBalance = 0;
        }

        // Generate withdraw profit transaction calldata
        bytes memory withdrawCalldata = abi.encodeWithSignature(
            "withdrawProfit(address,uint256)",
            RECIPIENT,
            WITHDRAW_AMOUNT
        );

        console2.log("\n====== Withdraw Transaction Details ======");
        console2.log("To: ", vaultProxyAddress);
        console2.log("Value: 0 ETH");
        console2.log("Function: withdrawProfit(address,uint256)");
        console2.log("Parameters:");
        console2.log("  - Recipient: ", RECIPIENT);
        console2.log("  - Amount: ", WITHDRAW_AMOUNT);
        console2.log("Data: ", _toHexString(withdrawCalldata));

        // Get token info
        address tokenAddress;
        try vault.token() returns (IERC20 token) {
            tokenAddress = address(token);
            console2.log("Token address: ", tokenAddress);
        } catch {
            console2.log(
                "[!] Warning: Could not fetch token address - verify vault address is correct"
            );
            tokenAddress = usdc; // Fallback to USDC from config
        }

        // Verify if the withdrawal is possible
        if (currentBalance < WITHDRAW_AMOUNT) {
            console2.log(
                "\n[!] Warning: Requested withdrawal amount exceeds current vault balance"
            );
            console2.log("    Available: ", currentBalance);
            console2.log("    Requested: ", WITHDRAW_AMOUNT);
        } else {
            console2.log("\n[+] Withdrawal amount is within available balance");
        }

        // Print instructions for executing the transaction
        _printSafeInstructions(withdrawCalldata);

        // Simulate the transaction execution
        vm.startPrank(safeWallet);

        bool success;
        bytes memory returnData;
        (success, returnData) = vaultProxyAddress.call(withdrawCalldata);

        vm.stopPrank();

        console2.log("\n====== Transaction Simulation ======");
        console2.log("Simulation success: ", success);
        if (!success) {
            console2.log("Simulation reverted. Please check parameters and permissions.");
            if (returnData.length > 0) {
                // Try to decode the revert reason
                console2.log("Revert reason: ", _decodeRevertReason(returnData));
            }
        } else {
            console2.log(
                "Simulation successful. Transaction should work when executed from Safe wallet."
            );
        }
    }

    function _printSafeInstructions(bytes memory withdrawCalldata) internal view {
        console2.log("\n====== How to Execute with Safe Wallet ======");
        console2.log("Option 1: Using Safe Web UI");
        console2.log("1. Go to https://app.safe.global");
        console2.log("2. Connect your wallet and select your Safe");
        console2.log("3. Create a new transaction with these parameters:");
        console2.log("   - To: ", vaultProxyAddress);
        console2.log("   - Value: 0");
        console2.log("   - Data: ", _toHexString(withdrawCalldata));
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
                _addressToString(vaultProxyAddress),
                '",',
                '"value": "0",',
                '"data": "',
                _toHexString(withdrawCalldata),
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

    // Helper function to decode revert reason
    function _decodeRevertReason(bytes memory returnData) internal pure returns (string memory) {
        // If the returnData length is less than 68, then the transaction failed silently
        if (returnData.length < 68) return "No revert reason";

        // Extract the revert reason from the response
        bytes memory revertData = _slice(returnData, 4, returnData.length - 4);

        // Check if it's an error string
        string memory reason = abi.decode(revertData, (string));

        return reason;
    }

    // Helper function to slice bytes
    function _slice(
        bytes memory data,
        uint256 start,
        uint256 length
    ) internal pure returns (bytes memory) {
        bytes memory result = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            result[i] = data[start + i];
        }
        return result;
    }
}
