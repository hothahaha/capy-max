// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {StrategyEngine} from "../src/StrategyEngine.sol";
import {CpToken} from "../src/tokens/CpToken.sol";
import {HelperConfig} from "../script/HelperConfig.s.sol";
import {DeployScript} from "../script/Deploy.s.sol";
import {Vault} from "../src/vault/Vault.sol";
import {SignerManager} from "../src/access/SignerManager.sol";
import {MultiSig} from "../src/access/MultiSig.sol";
import {IStrategyEngine} from "../src/interfaces/IStrategyEngine.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeableBase} from "../src/upgradeable/UUPSUpgradeableBase.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";

contract StrategyEngineV2 is StrategyEngine {
    // Add new function for testing upgrades
    uint256 public newVariable;
    bool public newFunctionCalled;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }

    // Add new platform fee related functions
    function getDefaultPlatformFee() external pure returns (uint256) {
        return 1000; // 10%
    }

    function newFunction() external {
        newFunctionCalled = true;
    }
}

contract StrategyEngineUpgradesTest is Test {
    StrategyEngine public engine;
    StrategyEngine public implementation;
    CpToken public cpToken;
    Vault public vault;
    SignerManager public signerManager;
    MultiSig public multiSig;
    HelperConfig public helperConfig;

    uint256 public deployerKey;
    address public wbtc;
    address public usdc;
    address public aavePool;
    address public aaveOracle;
    address public aaveProtocolDataProvider;
    address public tokenMessenger;
    bytes32 public solanaAddress;
    address public owner;
    address public user = makeAddr("user");
    address public signer1;
    uint256 public signer1Key;

    // 存储槽常量
    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 public constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    event Upgraded(address indexed implementation);

    error InvalidInitialization();
    error OwnableUnauthorizedAccount(address account);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        (signer1, signer1Key) = makeAddrAndKey("signer1");

        DeployScript deployer = new DeployScript();
        (engine, cpToken, vault, signerManager, multiSig, helperConfig) = deployer.run();
        (
            wbtc,
            usdc,
            aavePool,
            aaveOracle,
            aaveProtocolDataProvider,
            deployerKey,
            tokenMessenger,
            solanaAddress
        ) = helperConfig.activeNetworkConfig();

        // 获取实现合约地址
        address implAddress = address(
            uint160(uint256(vm.load(address(engine), IMPLEMENTATION_SLOT)))
        );
        implementation = StrategyEngine(implAddress);
    }

    function test_InitialSetup() public view {
        // Verify proxy contract setup
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(implementation));
        assertEq(engine.owner(), vm.addr(deployerKey), "Owner should be deployer address");
    }

    function test_UpgradeToV2() public {
        // Deploy new version contract
        StrategyEngineV2 newImplementation = new StrategyEngineV2();
        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // Execute upgrade
        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);

        // Verify new functionality after upgrade
        StrategyEngineV2(address(engine)).newFunction();
        assertTrue(StrategyEngineV2(address(engine)).newFunctionCalled());
    }

    function test_UpgradePreservesState() public {
        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(engineV2),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // Add second signer and set threshold
        _addSigner(signer2);
        _updateThreshold(2);

        // Ensure correct signature order
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // Execute upgrade
        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);

        // Verify state preservation
        StrategyEngineV2 upgradedEngine = StrategyEngineV2(address(engine));
        assertEq(upgradedEngine.getPlatformFee(), 800, "Platform fee not preserved after upgrade");
        assertTrue(
            signerManager.isSigner(vm.addr(deployerKey)),
            "Signer authorization not preserved"
        );
    }

    function test_CannotInitializeImplementation() public {
        // Try to initialize implementation contract directly
        vm.expectRevert(InvalidInitialization.selector);
        implementation.initialize(
            IStrategyEngine.EngineInitParams({
                wbtc: address(0),
                usdc: address(0),
                aavePool: address(0),
                aaveOracle: address(0),
                aaveProtocolDataProvider: address(0),
                cpToken: address(0),
                vault: address(0),
                multiSig: address(0),
                tokenMessenger: address(0),
                solanaAddress: bytes32(0)
            })
        );
    }

    function test_StorageSlotConsistency() public {
        // Set initial state
        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        // Upgrade to new version
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        // Ensure deployer is signer
        address deployer = vm.addr(deployerKey);
        if (!signerManager.isSigner(deployer)) {
            console2.log("Adding deployer as signer:", deployer);
            _addSigner(deployer);
        }

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(newImplementation),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // Add second signer and set threshold
        _addSigner(signer2);
        _updateThreshold(2);

        // Verify signer status
        require(signerManager.isSigner(signer2), "Signer2 not added successfully");
        console2.log("Deployer address:", deployer);
        console2.log("Signer2 address:", signer2);

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // Execute upgrade
        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);

        // Verify data preservation
        assertEq(engine.owner(), vm.addr(deployerKey));
        assertEq(
            StrategyEngineV2(address(engine)).getPlatformFee(),
            800,
            "Platform fee not preserved"
        );

        // Verify new functionality
        vm.prank(vm.addr(deployerKey));
        StrategyEngineV2(address(engine)).setNewVariable(123);
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 123);
    }

    function test_UpgradeToAndCall() public {
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(700);

        // Prepare initialization data
        bytes memory data = abi.encodeWithSelector(StrategyEngineV2.setNewVariable.selector, 999);

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(newImplementation),
            data
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // Add second signer and set threshold
        _addSigner(signer2);
        _updateThreshold(2);

        // Ensure correct signature order
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        // Execute upgrade
        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);

        // Verify initialization success
        assertEq(StrategyEngineV2(address(engine)).newVariable(), 999);
        assertEq(
            StrategyEngineV2(address(engine)).getPlatformFee(),
            700,
            "Platform fee not preserved after upgrade and call"
        );
        assertTrue(signerManager.isSigner(vm.addr(deployerKey)), "Signer status lost");
    }

    function test_ProxyAdmin() public view {
        // Verify proxy admin
        bytes32 adminSlot = vm.load(address(engine), ADMIN_SLOT);
        address admin = address(uint160(uint256(adminSlot)));
        assertEq(admin, address(0), "Proxy admin should be zero for UUPS");
    }

    function test_RevertWhen_UpgradeToSameImplementation() public {
        // Get current implementation contract address
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));

        // Add second signer and set threshold
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");
        _addSigner(signer2);
        _updateThreshold(2);

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            currentImpl,
            ""
        );

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);

        // Ensure correct signature order
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);
        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);
    }

    function test_UpgradeEvent() public {
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(engineV2),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // Ensure correct signature order
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(engineV2));

        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);
    }

    function test_UpgradeWithEmptyData() public {
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        // Add second signer and set threshold
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");
        _addSigner(signer2);
        _updateThreshold(2);

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            engineV2,
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);

        // Ensure correct signature order
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);

        // Verify upgrade success
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(engineV2));
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        // Deploy new contract
        StrategyEngineV2 engineV2 = new StrategyEngineV2();

        uint256 deadline = block.timestamp + 1 days;

        // Construct upgrade data
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            address(engineV2),
            ""
        );

        // Generate signatures
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        // Add second signer and set threshold
        _addSigner(signer2);
        _updateThreshold(2);

        // Generate signatures with unauthorized signer
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        // Get transaction hash
        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(unauthorizedKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);
    }

    function test_RevertWhen_InitializeAgain() public {
        vm.startBroadcast(vm.addr(deployerKey));
        vm.expectRevert(InvalidInitialization.selector);
        engine.initialize(
            IStrategyEngine.EngineInitParams({
                wbtc: wbtc,
                usdc: usdc,
                aavePool: aavePool,
                aaveOracle: aaveOracle,
                aaveProtocolDataProvider: aaveProtocolDataProvider,
                cpToken: address(cpToken),
                vault: address(vault),
                multiSig: address(multiSig),
                tokenMessenger: address(tokenMessenger),
                solanaAddress: solanaAddress
            })
        );
        vm.stopBroadcast();
    }

    // Helper functions
    function _hashTransaction(
        address verifyingContract,
        address to,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes32) {
        bytes32 txHash = MultiSig(verifyingContract).hashTransaction(to, data, nonce, deadline);
        return txHash;
    }

    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _addSigner(address signer) internal {
        bytes memory data = abi.encodeWithSelector(SignerManager.addSigner.selector, signer);
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            data,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }

    function _updateThreshold(uint256 newThreshold) internal {
        bytes memory data = abi.encodeWithSelector(
            SignerManager.updateThreshold.selector,
            newThreshold
        );
        uint256 deadline = block.timestamp + 1 days;

        bytes32 txHash = multiSig.hashTransaction(
            address(signerManager),
            data,
            multiSig.nonce(),
            deadline
        );

        bytes[] memory signatures = new bytes[](1);
        signatures[0] = _signTransaction(deployerKey, txHash);

        vm.prank(vm.addr(deployerKey));
        multiSig.executeTransaction(address(signerManager), data, deadline, signatures);
    }
}
