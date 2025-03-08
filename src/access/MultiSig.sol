// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {UUPSUpgradeableBase} from "../upgradeable/UUPSUpgradeableBase.sol";
import {SignerManager} from "./SignerManager.sol";

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

contract MultiSig is UUPSUpgradeableBase {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    // Errors
    error MultiSig__InvalidSignatureLength();
    error MultiSig__InvalidSignature();
    error MultiSig__InvalidNonce();
    error MultiSig__InvalidDeadline();
    error MultiSig__InvalidTarget();
    error MultiSig__ExecutionFailed();
    error MultiSig__InsufficientSignatures();
    error MultiSig__DuplicateSignature();

    // State variables
    SignerManager public signerManager;
    uint256 private _nonce;

    // Constants
    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 private constant TRANSACTION_TYPEHASH =
        keccak256("Transaction(address to,bytes data,uint256 nonce,uint256 deadline)");

    // Events
    event TransactionExecuted(address indexed to, bytes data, uint256 nonce, uint256 deadline);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address initialOwner, address _signerManager) external initializer {
        __UUPSUpgradeableBase_init(initialOwner);
        signerManager = SignerManager(_signerManager);
        transferUpgradeRights(address(this));
    }

    function executeTransaction(
        address to,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata signatures
    ) external returns (bytes memory) {
        // Verify target address
        if (to == address(0)) revert MultiSig__InvalidTarget();

        // Verify deadline
        if (block.timestamp > deadline) revert MultiSig__InvalidDeadline();

        // Get current required signature threshold
        uint256 threshold = signerManager.getThreshold();

        // Verify provided signature count
        if (signatures.length < threshold) {
            revert MultiSig__InsufficientSignatures();
        }

        // Calculate transaction hash
        bytes32 ethSignedHash = _hashTransaction(to, data, _nonce, deadline);

        // Record valid signers count
        uint256 validSignersCount = 0;
        address[] memory recoveredSigners = new address[](signatures.length);

        // Verify all signatures
        for (uint256 i = 0; i < signatures.length; i++) {
            // Verify signature length
            if (signatures[i].length != 65) revert MultiSig__InvalidSignatureLength();

            // Recover signer address
            address signer = _recoverSigner(ethSignedHash, signatures[i]);

            // Verify signer permission
            if (!signerManager.isSigner(signer)) {
                revert MultiSig__InvalidSignature();
            }

            // Check duplicate signature
            for (uint256 j = 0; j < i; j++) {
                if (signer == recoveredSigners[j]) {
                    revert MultiSig__DuplicateSignature();
                }
            }

            recoveredSigners[i] = signer;
            validSignersCount++;
        }

        // Verify again valid signature count
        if (validSignersCount < threshold) {
            revert MultiSig__InsufficientSignatures();
        }

        // Increase nonce
        _nonce++;

        // Execute transaction
        (bool success, bytes memory result) = to.call(data);
        if (!success) {
            revert MultiSig__ExecutionFailed();
        }

        emit TransactionExecuted(to, data, _nonce - 1, deadline);
        return result;
    }

    function hashTransaction(
        address to,
        bytes calldata data,
        uint256 nonce_,
        uint256 deadline
    ) external view returns (bytes32) {
        return _hashTransaction(to, data, nonce_, deadline);
    }

    function _hashTransaction(
        address to,
        bytes calldata data,
        uint256 nonce_,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 domainSeparator = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256("MultiSig"),
                keccak256("1"),
                block.chainid,
                address(this)
            )
        );

        bytes32 structHash = keccak256(
            abi.encode(TRANSACTION_TYPEHASH, to, keccak256(data), nonce_, deadline)
        );

        bytes32 txHash = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));

        bytes32 ethSignedHash = txHash.toEthSignedMessageHash();

        return ethSignedHash;
    }

    function _recoverSigner(bytes32 hash, bytes memory signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return ecrecover(hash, v, r, s);
    }

    function nonce() external view returns (uint256) {
        return _nonce;
    }

    function getSignerManager() external view returns (SignerManager) {
        return signerManager;
    }
}
