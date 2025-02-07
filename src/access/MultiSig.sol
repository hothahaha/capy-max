// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {SignerManager} from "./SignerManager.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

contract MultiSig is Initializable, UUPSUpgradeable, OwnableUpgradeable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    error MultiSig__InvalidSignatureLength();
    error MultiSig__InvalidSignature();
    error MultiSig__InvalidNonce();
    error MultiSig__InvalidDeadline();
    error MultiSig__InvalidTarget();
    error MultiSig__ExecutionFailed();
    error MultiSig__InsufficientSignatures();
    error MultiSig__DuplicateSignature();
    error MultiSig__InvalidImplementation();
    error MultiSig__Unauthorized();

    SignerManager public signerManager;
    uint256 private _nonce;

    bytes32 private constant DOMAIN_TYPEHASH =
        keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );

    bytes32 private constant TRANSACTION_TYPEHASH =
        keccak256(
            "Transaction(address to,bytes data,uint256 nonce,uint256 deadline)"
        );

    event TransactionExecuted(
        address indexed to,
        bytes data,
        uint256 nonce,
        uint256 deadline
    );

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _signerManager) public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
        signerManager = SignerManager(_signerManager);
    }

    function _authorizeUpgrade(
        address newImplementation
    ) internal view override onlyOwner {
        // 检查新实现合约地址是否为零地址
        if (newImplementation == address(0)) {
            revert MultiSig__InvalidImplementation();
        }
    }

    function executeTransaction(
        address to,
        bytes calldata data,
        uint256 deadline,
        bytes[] calldata signatures
    ) external {
        // 验证目标地址
        if (to == address(0)) revert MultiSig__InvalidTarget();

        // 验证deadline
        if (block.timestamp > deadline) revert MultiSig__InvalidDeadline();

        // 验证签名数量
        uint256 threshold = signerManager.getThreshold();
        if (signatures.length < threshold)
            revert MultiSig__InsufficientSignatures();

        // 计算交易哈希
        bytes32 txHash = _hashTransaction(to, data, _nonce, deadline);
        bytes32 ethSignedHash = txHash.toEthSignedMessageHash();

        // 验证签名
        address[] memory recoveredSigners = new address[](signatures.length);
        for (uint256 i = 0; i < signatures.length; i++) {
            // 验证签名长度
            if (signatures[i].length != 65)
                revert MultiSig__InvalidSignatureLength();

            // 恢复签名者地址
            address signer = _recoverSigner(ethSignedHash, signatures[i]);

            // 验证签名者权限
            if (!signerManager.isSigner(signer))
                revert MultiSig__InvalidSignature();

            // 检查重复签名
            for (uint256 j = 0; j < i; j++) {
                if (signer == recoveredSigners[j])
                    revert MultiSig__DuplicateSignature();
            }
            recoveredSigners[i] = signer;
        }

        // 增加nonce
        _nonce++;

        // 执行交易
        (bool success, ) = to.call(data);
        if (!success) revert MultiSig__ExecutionFailed();

        emit TransactionExecuted(to, data, _nonce - 1, deadline);
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
            abi.encode(
                TRANSACTION_TYPEHASH,
                to,
                keccak256(data),
                nonce_,
                deadline
            )
        );

        return
            keccak256(
                abi.encodePacked("\x19\x01", domainSeparator, structHash)
            );
    }

    function _recoverSigner(
        bytes32 hash,
        bytes memory signature
    ) internal pure returns (address) {
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
}
