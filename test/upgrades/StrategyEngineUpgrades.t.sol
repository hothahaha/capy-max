// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {console} from "forge-std/Test.sol";
import {BaseContractUpgradeTest} from "./BaseContractUpgradeTest.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {IStrategyEngine} from "../../src/interfaces/IStrategyEngine.sol";

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {UUPSUpgradeableBase} from "../../src/upgradeable/UUPSUpgradeableBase.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {BaseV2Contract} from "./BaseV2Contract.sol";
import {ITransparentUpgradeableProxy} from "@openzeppelin/contracts/proxy/transparent/TransparentUpgradeableProxy.sol";

contract StrategyEngineV2 is StrategyEngine, BaseV2Contract {
    function getDefaultPlatformFee() external pure returns (uint256) {
        return 1000;
    }
}

contract StrategyEngineUpgradesTest is BaseContractUpgradeTest {
    StrategyEngine internal engine;
    StrategyEngineV2 internal engineV2;
    CpToken internal cpToken;
    Vault internal vault;

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
    bytes32 public constant ADMIN_SLOT =
        0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    error InvalidInitialization();
    error OwnableUnauthorizedAccount(address account);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");
        (signer1, signer1Key) = makeAddrAndKey("signer1");

        DeployScript deployer = new DeployScript();
        (engine, cpToken, vault, signerManager, multiSig, helperConfig) = deployer.run();
        (, , , , , deployerKey, , ) = helperConfig.activeNetworkConfig();

        engineV2 = new StrategyEngineV2();
    }

    function getUpgradeableContract() public view override returns (address) {
        return address(engine);
    }

    function getNewImplementation() public view override returns (address) {
        return address(engineV2);
    }

    function validateUpgrade() public override {
        assertEq(StrategyEngineV2(address(engine)).version(), "V2");
        assertEq(StrategyEngineV2(address(engine)).getDefaultPlatformFee(), 1000);

        // Test new functionality
        StrategyEngineV2(address(engine)).newFunction();
        assertTrue(StrategyEngineV2(address(engine)).newFunctionCalled());
    }

    function test_StorageSlotConsistency() public {
        // Set initial state
        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(800);

        // Perform upgrade
        address implementation = getNewImplementation();
        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            implementation
        );
        _executeUpgradeTest(params);

        // Verify data preservation
        assertEq(engine.owner(), vm.addr(deployerKey));
        assertEq(
            StrategyEngineV2(address(engine)).getPlatformFee(),
            800,
            "Platform fee not preserved after upgrade"
        );
    }

    function test_UpgradeToAndCall() public {
        // Set initial state
        vm.prank(vm.addr(deployerKey));
        engine.updatePlatformFee(700);

        // 直接执行升级，避免使用辅助函数
        _directUpgrade(address(engineV2));

        engineV2.setNewVariable(999);

        // Verify initialization
        assertEq(engineV2.newVariable(), 999);
        assertEq(engine.getPlatformFee(), 700, "Platform fee not preserved");
    }

    function test_RevertWhen_InitializeAgain() public {
        vm.startBroadcast(vm.addr(deployerKey));
        vm.expectRevert(InvalidInitialization.selector);
        engine.initialize(
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
        vm.stopBroadcast();
    }

    function test_ProxyAdmin() public view {
        bytes32 adminSlot = vm.load(address(engine), ADMIN_SLOT);
        address admin = address(uint160(uint256(adminSlot)));
        assertEq(admin, address(0), "Proxy admin should be zero for UUPS");
    }

    function test_RevertWhen_UpgradeToSameImplementation() public {
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));

        UpgradeTestParams memory params = _prepareUpgradeTest(
            getUpgradeableContract(),
            currentImpl
        );

        vm.expectRevert(MultiSig.MultiSig__ExecutionFailed.selector);
        _executeUpgradeTest(params);
    }

    function test_UpgradeWithEmptyData() public {
        // 拆分为多个步骤，减少栈深度
        address signer2;
        uint256 signer2Key;
        (signer2, signer2Key) = makeAddrAndKey("signer2");
        _addSigner(signer2);
        _updateThreshold(2);

        // 执行升级
        _executeUpgradeWithSigners(address(engineV2), deployerKey, signer2Key);

        // Verify upgrade success
        bytes32 implSlot = vm.load(address(engine), IMPLEMENTATION_SLOT);
        address currentImpl = address(uint160(uint256(implSlot)));
        assertEq(currentImpl, address(engineV2));
    }

    function test_RevertWhen_UpgradeDirectly() public override {
        StrategyEngineV2 newImplementation = new StrategyEngineV2();

        vm.prank(vm.addr(deployerKey));
        vm.expectRevert(UUPSUpgradeableBase.UUPSUpgradeableBase__Unauthorized.selector);
        UUPSUpgradeableBase(getUpgradeableContract()).upgradeToAndCall(
            address(newImplementation),
            ""
        );
    }

    function _directUpgrade(address newImplementation) internal {
        // 直接通过 MultiSig 执行升级
        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            newImplementation,
            ""
        );

        vm.prank(address(multiSig));
        (bool success, ) = address(engine).call(upgradeData);
        require(success, "Upgrade failed");
    }

    function _executeUpgradeWithSigners(
        address newImplementation,
        uint256 key1,
        uint256 key2
    ) internal {
        uint256 deadline = block.timestamp + 1 days;

        bytes memory upgradeData = abi.encodeWithSelector(
            engine.upgradeToAndCall.selector,
            newImplementation,
            ""
        );

        bytes[] memory signatures = new bytes[](2);

        bytes32 txHash = multiSig.hashTransaction(
            address(engine),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(key1, txHash);
        signatures[1] = _signTransaction(key2, txHash);

        multiSig.executeTransaction(address(engine), upgradeData, deadline, signatures);
    }
}
