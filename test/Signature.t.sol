// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Permit.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {DeployScript} from "../script/Deploy.s.sol";
import {Signature} from "../src/utils/Signature.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {StrategyEngine} from "../src/strategyEngine.sol";

contract SignatureTest is Test {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    address public wbtc;
    address public usdc;
    address public owner;
    uint256 public ownerPrivateKey;
    address public spender;
    uint256 public constant AMOUNT = 1000e8; // 1000 WBTC with 8 decimals
    uint256 public constant DEADLINE = type(uint256).max;

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (, , HelperConfig config) = deployer.run();
        (wbtc, usdc, , , ) = config.activeNetworkConfig();

        // Create owner with private key
        (owner, ownerPrivateKey) = makeAddrAndKey("owner");
        spender = makeAddr("spender");

        // Deal tokens to owner
        deal(wbtc, owner, AMOUNT);
        deal(usdc, owner, AMOUNT);
    }

    function test_WBTCPermitSignatureValidation() public {
        _testPermitSignature(wbtc);
    }

    function test_USDCPermitSignatureValidation() public {
        _testPermitSignature(usdc);
    }

    function _testPermitSignature(address token) internal {
        // Get current nonce
        uint256 nonce = IERC20Permit(token).nonces(owner);

        // Generate signature using our library
        (uint8 v, bytes32 r, bytes32 s) = _getPermitSignature(
            token,
            AMOUNT,
            DEADLINE,
            nonce,
            ownerPrivateKey
        );

        // Verify signature using ECRecover
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, AMOUNT, nonce, DEADLINE)
        );

        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                IERC20Permit(token).DOMAIN_SEPARATOR(),
                structHash
            )
        );

        // Recover signer using ECDSA
        address recoveredSigner = ECDSA.recover(digest, v, r, s);

        // Verify recovered signer matches owner
        assertEq(recoveredSigner, owner, "Invalid signature: signer mismatch");

        // Verify permit works with the signature
        vm.startPrank(owner);
        IERC20Permit(token).permit(owner, spender, AMOUNT, DEADLINE, v, r, s);
        vm.stopPrank();

        // Verify allowance was set
        assertEq(
            IERC20(token).allowance(owner, spender),
            AMOUNT,
            "Permit failed: allowance not set"
        );
    }

    // Helper functions
    function _getPermitSignature(
        address token,
        uint256 amount,
        uint256 deadline,
        uint256 nonce,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        bytes32 PERMIT_TYPEHASH = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        // Use the token's own DOMAIN_SEPARATOR
        bytes32 DOMAIN_SEPARATOR = IERC20Permit(token).DOMAIN_SEPARATOR();

        // messageHash
        bytes32 messageHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, amount, nonce, deadline)
        );

        // Compute the digest
        bytes32 digest = keccak256(
            abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, messageHash)
        );

        // Generate signature
        (v, r, s) = vm.sign(privateKey, digest);
    }
}
