// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";

/// @title Signature
/// @notice Utility library for generating EIP-2612 permit signatures
library Signature {
    // Custom errors
    error Signature__InvalidLength();
    error Signature__InvalidSignature();

    /// @notice Generates EIP-2612 permit signature parameters
    /// @param token The token address
    /// @param owner The token owner
    /// @param spender The approved spender
    /// @param value The amount of tokens
    /// @param deadline The permit deadline
    /// @param privateKey The private key to sign with (only used in tests)
    function getPermitSignature(
        address token,
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        // Get current nonce for owner
        uint256 nonce = IERC20Permit(token).nonces(owner);

        // Get domain separator from token contract
        bytes32 DOMAIN_SEPARATOR = IERC20Permit(token).DOMAIN_SEPARATOR();

        // Compute permit hash
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline)
        );

        // Compute final digest
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash)
        );

        // For testing environments that support vm.sign
        if (privateKey != 0) {
            assembly {
                // Get free memory pointer
                let memPtr := mload(0x40)

                // Call vm.sign cheatcode
                let success := staticcall(
                    gas(),
                    0x7109709ECfa91a80626fF3989D68f67F5b1DD12D, // vm address
                    privateKey,
                    digest,
                    memPtr,
                    0x60 // 96 bytes for v, r, s
                )

                // If successful, extract v, r, s
                if success {
                    r := mload(memPtr)
                    s := mload(add(memPtr, 0x20))
                    v := byte(0, mload(add(memPtr, 0x40)))
                }
            }
        }

        return (v, r, s);
    }

    /// @notice Splits a raw signature into v, r, s components
    /// @param signature The raw signature bytes
    function splitSignature(
        bytes memory signature
    ) internal pure returns (uint8 v, bytes32 r, bytes32 s) {
        if (signature.length != 65) revert Signature__InvalidLength();

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v != 27 && v != 28) revert Signature__InvalidSignature();
    }
}
