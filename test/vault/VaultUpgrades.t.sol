// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {MultiSig} from "../../src/access/MultiSig.sol";
import {SignerManager} from "../../src/access/SignerManager.sol";

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract VaultV2 is Vault {
    uint256 public newVariable;

    function setNewVariable(uint256 _value) external {
        newVariable = _value;
    }

    function version() external pure returns (string memory) {
        return "V2";
    }
}

contract VaultUpgradesTest is Test {
    StrategyEngine public engine;
    Vault public vault;
    IERC20 public usdc;
    HelperConfig public helperConfig;
    MultiSig public multiSig;
    SignerManager public signerManager;

    address public owner;
    address public user;
    uint256 public deployerKey;

    bytes32 public constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    event Upgraded(address indexed implementation);

    function setUp() public {
        owner = makeAddr("owner");
        user = makeAddr("user");

        DeployScript deployer = new DeployScript();
        (engine, , vault, signerManager, multiSig, helperConfig) = deployer
            .run();
        address usdcAddress;
        (, usdcAddress, deployerKey) = helperConfig.activeNetworkConfig();
        usdc = IERC20(usdcAddress);
        owner = address(engine);

        // Deal some USDC to user
        deal(address(usdc), user, 1000e6);
    }

    function test_UpgradeToV2() public {
        VaultV2 vaultV2 = new VaultV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(vaultV2),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // 确保使用正确的签名顺序
        address deployer = vm.addr(deployerKey);
        require(signerManager.isSigner(deployer), "Deployer not a signer");
        require(signerManager.isSigner(signer2), "Signer2 not a signer");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(vault),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(deployerKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(vaultV2));

        multiSig.executeTransaction(
            address(vault),
            upgradeData,
            deadline,
            signatures
        );

        VaultV2 upgradedVault = VaultV2(address(vault));
        assertEq(upgradedVault.version(), "V2");
    }

    function test_RevertWhen_UpgradeUnauthorized() public {
        VaultV2 vaultV2 = new VaultV2();

        uint256 deadline = block.timestamp + 1 days;

        // 构造升级数据
        bytes memory upgradeData = abi.encodeWithSelector(
            vault.upgradeToAndCall.selector,
            address(vaultV2),
            ""
        );

        // 生成签名
        bytes[] memory signatures = new bytes[](2);
        (address signer2, uint256 signer2Key) = makeAddrAndKey("signer2");

        _addSigner(signer2);
        _updateThreshold(2);

        // 使用未授权的签名者生成签名
        (, uint256 unauthorizedKey) = makeAddrAndKey("unauthorized");

        // 获取交易哈希
        bytes32 txHash = multiSig.hashTransaction(
            address(vault),
            upgradeData,
            multiSig.nonce(),
            deadline
        );

        signatures[0] = _signTransaction(unauthorizedKey, txHash);
        signatures[1] = _signTransaction(signer2Key, txHash);

        vm.expectRevert(MultiSig.MultiSig__InvalidSignature.selector);
        multiSig.executeTransaction(
            address(vault),
            upgradeData,
            deadline,
            signatures
        );
    }

    // Helper functions
    function _signTransaction(
        uint256 privateKey,
        bytes32 digest
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _addSigner(address signer) internal {
        bytes memory data = abi.encodeWithSelector(
            SignerManager.addSigner.selector,
            signer
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
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
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
        multiSig.executeTransaction(
            address(signerManager),
            data,
            deadline,
            signatures
        );
    }
}
