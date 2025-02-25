// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {VerifyDeployment} from "../script/VerifyDeployment.s.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {Vault} from "../src/vault/Vault.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {UUPSUpgradeableBase} from "../src/upgradeable/UUPSUpgradeableBase.sol";

import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract VerifyDeploymentTest is Test {
    struct TestParams {
        address target;
        bytes data;
        uint256 deadline;
        bytes[] signatures;
    }

    struct SignerParams {
        address signer;
        uint256 deadline;
        bytes[] signatures;
        bytes data;
    }

    struct UpgradeTestParams {
        address implementation;
        bytes[] signatures;
        uint256 deadline;
        bytes32 txHash;
    }

    VerifyDeployment public verifier;
    MultiSig public multiSig;
    SignerManager public signerManager;
    HelperConfig public helperConfig;
    Vault public vault;
    StrategyEngine public engine;
    address public vaultProxy;
    address public engineProxy;

    address public signer1;
    address public signer2;
    uint256 public signer1Key;
    uint256 public signer2Key;
    uint256 public deployerKey;

    function setUp() public {
        DeployScript deployer = new DeployScript();
        (engine, , vault, signerManager, multiSig, helperConfig) = deployer.run();
        vaultProxy = address(vault);
        engineProxy = address(engine);
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();
        verifier = new VerifyDeployment();

        (signer1, signer1Key) = makeAddrAndKey("signer1");
        (signer2, signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer1);
        _addSigner(signer2);
        _updateThreshold(2);
    }

    function _prepareUpgradeTest(address implementation) internal view returns (TestParams memory) {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            implementation,
            ""
        );

        bytes32 txHash = multiSig.hashTransaction(
            vaultProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        return
            TestParams({
                target: vaultProxy,
                data: upgradeData,
                deadline: deadline,
                signatures: signatures
            });
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 txHash
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, txHash);
        return abi.encodePacked(r, s, v);
    }

    function _executeMultiSigTx(TestParams memory params) internal {
        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(params.target, params.data, params.deadline, params.signatures);
    }

    function _prepareDeployTest() internal view returns (TestParams memory) {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory deployData = abi.encodeWithSelector(DeployScript.run.selector);

        bytes32 txHash = multiSig.hashTransaction(
            address(verifier),
            deployData,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](2);
        signatures[0] = _signTransaction(signer1Key, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        return
            TestParams({
                target: address(verifier),
                data: deployData,
                deadline: deadline,
                signatures: signatures
            });
    }

    function test_VerifyAndDeploy() public {
        TestParams memory params = _prepareDeployTest();
        verifier.verifyAndDeploy(address(multiSig), params.signatures, params.deadline);
    }

    function test_RevertWhen_DeadlineExpired() public {
        uint256 deadline = block.timestamp - 1;
        bytes[] memory signatures = new bytes[](2);

        vm.expectRevert(VerifyDeployment.VerifyDeployment__Expired.selector);
        verifier.verifyAndDeploy(address(multiSig), signatures, deadline);
    }

    function test_RevertWhen_InsufficientSignatures() public {
        uint256 deadline = block.timestamp + 1 days;
        bytes[] memory signatures = new bytes[](1);

        vm.expectRevert(VerifyDeployment.VerifyDeployment__InsufficientSignatures.selector);
        verifier.verifyAndDeploy(address(multiSig), signatures, deadline);
    }

    function test_RevertWhen_InvalidSignature() public {
        TestParams memory params = _prepareDeployTest();
        (, uint256 invalidKey) = makeAddrAndKey("invalidSigner");
        params.signatures[1] = _signTransaction(invalidKey, keccak256("invalid"));

        vm.expectRevert(VerifyDeployment.VerifyDeployment__InvalidSignature.selector);
        verifier.verifyAndDeploy(address(multiSig), params.signatures, params.deadline);
    }

    function test_VerifyAndUpgrade() public {
        // Deploy new implementation contract
        Vault newImplementation = new Vault();

        TestParams memory params = _prepareUpgradeTest(address(newImplementation));

        // Execute verification and upgrade
        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            address(newImplementation),
            params.signatures,
            params.deadline
        );

        // Verify upgrade success
        assertEq(Vault(params.target).implementation(), address(newImplementation));
    }

    function _testRevertWithError(
        address implementation,
        bytes4 errorSelector,
        TestParams memory params
    ) internal {
        vm.expectRevert(errorSelector);
        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            implementation,
            params.signatures,
            params.deadline
        );
    }

    function test_RevertWhen_UpgradeWithInvalidSignatures() public {
        (, uint256 invalidKey) = makeAddrAndKey("invalidSigner");
        uint256[] memory keys = new uint256[](2);
        keys[0] = signer1Key;
        keys[1] = invalidKey;

        _testRevertWithError(
            address(new Vault()),
            VerifyDeployment.VerifyDeployment__InvalidSignature.selector,
            _prepareUpgradeParams(address(new Vault()), keys)
        );
    }

    function test_VerifyAndUpgradeEngine() public {
        // Deploy new implementation contract
        StrategyEngine newImplementation = new StrategyEngine();

        TestParams memory params = _prepareUpgradeTest(address(newImplementation));

        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            address(newImplementation),
            params.signatures,
            params.deadline
        );

        assertEq(StrategyEngine(params.target).implementation(), address(newImplementation));
    }

    function test_RevertWhen_UpgradeToZeroAddress() public {
        TestParams memory params = _prepareUpgradeTest(address(0));

        vm.expectRevert(VerifyDeployment.VerifyDeployment__UpgradeFailed.selector);
        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            address(0),
            params.signatures,
            params.deadline
        );
    }

    function test_RevertWhen_UpgradeWithExpiredDeadline() public {
        Vault newImplementation = new Vault();
        TestParams memory params = _prepareUpgradeTest(address(newImplementation));

        // 确保先检查过期时间
        uint256 expiredDeadline = block.timestamp - 1;

        vm.expectRevert(VerifyDeployment.VerifyDeployment__Expired.selector);
        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            address(newImplementation),
            params.signatures, // 使用有效签名
            expiredDeadline // 使用过期时间
        );
    }

    function test_RevertWhen_UpgradeWithInsufficientSignatures() public {
        Vault newImplementation = new Vault();
        TestParams memory params = _prepareUpgradeTest(address(newImplementation));

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(signer1Key, keccak256("dummy hash"));

        vm.expectRevert(VerifyDeployment.VerifyDeployment__InsufficientSignatures.selector);
        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            address(newImplementation),
            signatures,
            params.deadline
        );
    }

    function test_RevertWhen_UpgradeWithDuplicateSignatures() public {
        Vault newImplementation = new Vault();
        uint256[] memory keys = new uint256[](2);
        keys[0] = signer1Key;
        keys[1] = signer1Key;

        TestParams memory params = _prepareUpgradeParams(address(newImplementation), keys);

        vm.expectRevert(VerifyDeployment.VerifyDeployment__DuplicateSigner.selector);
        verifier.verifyAndUpgrade(
            address(multiSig),
            params.target,
            address(newImplementation),
            params.signatures,
            params.deadline
        );
    }

    // Helper functions
    function _addSigner(address signer) internal {
        bytes memory data = abi.encodeWithSelector(SignerManager.addSigner.selector, signer);
        uint256 deadline = block.timestamp + 1 days;
        bytes[] memory signatures = new bytes[](1);

        signatures[0] = _signTransaction(
            deployerKey,
            multiSig.hashTransaction(address(signerManager), data, multiSig.nonce(), deadline)
        );

        _executeMultiSigTx(
            TestParams({
                target: address(signerManager),
                data: data,
                deadline: deadline,
                signatures: signatures
            })
        );
    }

    function _updateThreshold(uint256 newThreshold) internal {
        _executeMultiSigTx(
            TestParams({
                target: address(signerManager),
                data: abi.encodeWithSelector(SignerManager.updateThreshold.selector, newThreshold),
                deadline: block.timestamp + 1 days,
                signatures: _getSignatures(
                    deployerKey,
                    address(signerManager),
                    abi.encodeWithSelector(SignerManager.updateThreshold.selector, newThreshold)
                )
            })
        );
    }

    function _getSignatures(
        uint256 signerKey,
        address target,
        bytes memory data
    ) internal view returns (bytes[] memory) {
        bytes[] memory signatures = new bytes[](1);
        uint256 deadline = block.timestamp + 1 days;

        signatures[0] = _signTransaction(
            signerKey,
            multiSig.hashTransaction(target, data, multiSig.nonce(), deadline)
        );
        return signatures;
    }

    function _prepareUpgradeParams(
        address implementation,
        uint256[] memory signerKeys
    ) internal view returns (TestParams memory) {
        uint256 deadline = block.timestamp + 1 days;
        bytes memory upgradeData = abi.encodeWithSelector(
            ITransparentUpgradeableProxy.upgradeToAndCall.selector,
            implementation,
            ""
        );

        bytes32 txHash = multiSig.hashTransaction(
            vaultProxy,
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        return
            TestParams({
                target: vaultProxy,
                data: upgradeData,
                deadline: deadline,
                signatures: _generateSignatures(txHash, signerKeys)
            });
    }

    function _generateSignatures(
        bytes32 txHash,
        uint256[] memory signerKeys
    ) internal pure returns (bytes[] memory) {
        bytes[] memory signatures = new bytes[](signerKeys.length);

        unchecked {
            for (uint256 i; i < signerKeys.length; ++i) {
                signatures[i] = _signTransaction(signerKeys[i], txHash);
            }
        }

        return signatures;
    }
}
