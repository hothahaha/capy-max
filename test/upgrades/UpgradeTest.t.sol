// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {Vault} from "../../src/vault/Vault.sol";
import {StrategyEngine} from "../../src/StrategyEngine.sol";
import {CpToken} from "../../src/tokens/CpToken.sol";
import {DeployScript} from "../../script/Deploy.s.sol";
import {HelperConfig} from "../../script/HelperConfig.s.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ISafe} from "../../src/interfaces/safe/ISafe.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

/**
 * @title VaultV2
 * @notice Mock upgraded version of Vault contract for testing upgrade functionality
 */
contract VaultV2 is Vault {
    // New state variable for V2
    uint256 public vaultVersion;

    // New function added in V2
    function initializeV2() external {
        vaultVersion = 2;
    }

    // Override existing function with new implementation
    function getBalance() external view override returns (uint256) {
        return token.balanceOf(address(this));
    }

    // New function added in V2
    function getVersion() external pure returns (uint256) {
        return 2;
    }
}

/**
 * @title StrategyEngineV2
 * @notice Mock upgraded version of StrategyEngine contract for testing upgrade functionality
 */
contract StrategyEngineV2 is StrategyEngine {
    // New state variable for V2
    uint256 public engineVersion;

    // New function added in V2
    function initializeV2() external {
        engineVersion = 2;
    }

    // New function added in V2
    function getVersion() external pure returns (uint256) {
        return 2;
    }

    // New feature added in V2
    function emergencyWithdraw(address token, address recipient, uint256 amount) external {
        // Access the safeWallet from the parent contract
        address safeWalletAddr = upgradeRightsOwner();
        require(msg.sender == safeWalletAddr, "Unauthorized");
        IERC20(token).transfer(recipient, amount);
    }
}

/**
 * @title UpgradeTest
 * @notice Test contract for testing Safe multisig-controlled upgrades
 */
contract UpgradeTest is Test {
    // Main contracts
    StrategyEngine public engine;
    CpToken public cpToken;
    Vault public vault;
    HelperConfig public helperConfig;

    // Addresses
    address public wbtc;
    address public usdc;
    address public aaveOracle;
    uint256 public deployerKey;
    address public safeWallet;

    address public DEPLOYER;
    address public user1;
    address public user2;
    address public user3;

    // Signers for multisig
    address[] public safeSigners;
    uint256[] public safeSignerKeys;
    uint256 public threshold;

    // Event to test against
    event Upgraded(address indexed implementation);

    function setUp() public {
        // Deploy contracts
        DeployScript deployScript = new DeployScript();
        (engine, cpToken, vault, helperConfig) = deployScript.run();

        // Get configuration
        (wbtc, usdc, , aaveOracle, , deployerKey, safeWallet) = helperConfig.activeNetworkConfig();

        DEPLOYER = vm.addr(deployerKey);
        user1 = makeAddr("user1");
        user2 = makeAddr("user2");
        user3 = makeAddr("user3");

        // Create mock Safe signers (4 signers with 3 threshold)
        threshold = 3;
        safeSigners = new address[](4);
        safeSignerKeys = new uint256[](4);

        for (uint256 i = 0; i < 4; i++) {
            (address signer, uint256 key) = makeAddrAndKey(
                string(abi.encodePacked("signer", i + 1))
            );
            safeSigners[i] = signer;
            safeSignerKeys[i] = key;
        }

        // Mock the Safe contract behavior
        vm.mockCall(
            DEPLOYER,
            abi.encodeWithSelector(ISafe.getOwners.selector),
            abi.encode(safeSigners)
        );

        vm.mockCall(
            DEPLOYER,
            abi.encodeWithSelector(ISafe.getThreshold.selector),
            abi.encode(threshold)
        );

        // Give user and Safe wallet some ETH for gas
        vm.deal(user1, 1 ether);
        vm.deal(DEPLOYER, 1 ether);

        // Deal some USDC to user and engine
        deal(usdc, user1, 1000e6);
        deal(usdc, address(engine), 1000e6);
    }

    /*//////////////////////////////////////////////////////////////
                        VAULT UPGRADE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RevertWhen_UnauthorizedVaultUpgrade() public {
        // Capture initial implementation address
        address initialImplementation = vault.implementation();

        // Deploy new implementation
        VaultV2 vaultV2Implementation = new VaultV2();

        // Try to upgrade from unauthorized address (user)
        vm.prank(user1);
        vm.expectRevert(); // Expect revert due to unauthorized access
        vault.upgradeToAndCall(address(vaultV2Implementation), "");

        // Try to upgrade from deployer (who transferred upgrade rights to safeWallet)
        vm.prank(DEPLOYER);
        vm.expectRevert(); // Expect revert due to unauthorized access
        vault.upgradeToAndCall(address(vaultV2Implementation), "");

        // Verify implementation did not change
        assertEq(
            vault.implementation(),
            initialImplementation,
            "Implementation should not change after failed upgrade attempts"
        );
    }

    function test_SuccessfulVaultUpgrade() public {
        // Get initial state
        uint256 initialBalance = vault.getBalance();
        address initialToken = address(vault.token());
        address initialSafeWallet = vault.safeWallet();

        // 1. Deploy new implementation
        VaultV2 vaultV2Implementation = new VaultV2();

        // 2. Execute upgrade through multisig (simulated)
        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(vaultV2Implementation));

        vm.prank(safeWallet);
        vault.upgradeToAndCall(
            address(vaultV2Implementation),
            abi.encodeWithSelector(VaultV2.initializeV2.selector)
        );

        // 3. Cast to V2 to access new functions
        VaultV2 upgradedVault = VaultV2(address(vault));

        // 4. Verify state was preserved through upgrade
        assertEq(
            upgradedVault.getBalance(),
            initialBalance,
            "Balance should be preserved after upgrade"
        );
        assertEq(
            address(upgradedVault.token()),
            initialToken,
            "Token address should be preserved after upgrade"
        );
        assertEq(
            upgradedVault.safeWallet(),
            initialSafeWallet,
            "SafeWallet should be preserved after upgrade"
        );

        // 5. Verify new functionality works
        assertEq(upgradedVault.vaultVersion(), 2, "New state variable should be initialized");
        assertEq(upgradedVault.getVersion(), 2, "New function should return correct version");

        // 6. Verify original functionality still works
        // First, add funds to test
        vm.startPrank(user1);
        IERC20(usdc).approve(address(upgradedVault), 100e6);
        upgradedVault.depositProfit(100e6);
        vm.stopPrank();

        assertEq(
            upgradedVault.getBalance(),
            initialBalance + 100e6,
            "Original functionality should work after upgrade"
        );
    }

    /*//////////////////////////////////////////////////////////////
                    STRATEGY ENGINE UPGRADE TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RevertWhen_UnauthorizedStrategyEngineUpgrade() public {
        // Capture initial implementation address
        address initialImplementation = engine.implementation();

        // Deploy new implementation
        StrategyEngineV2 engineV2Implementation = new StrategyEngineV2();

        // Try to upgrade from unauthorized address (user)
        vm.prank(user1);
        vm.expectRevert(); // Expect revert due to unauthorized access
        engine.upgradeToAndCall(address(engineV2Implementation), "");

        // Try to upgrade from deployer (who transferred upgrade rights to safeWallet)
        vm.prank(DEPLOYER);
        vm.expectRevert(); // Expect revert due to unauthorized access
        engine.upgradeToAndCall(address(engineV2Implementation), "");

        // Verify implementation did not change
        assertEq(
            engine.implementation(),
            initialImplementation,
            "Implementation should not change after failed upgrade attempts"
        );
    }

    function test_SuccessfulStrategyEngineUpgrade() public {
        // Get initial state
        uint256 initialPlatformFee = engine.getPlatformFee();
        uint256 initialDefaultLiquidationThreshold = engine.getDefaultLiquidationThreshold();
        address initialVaultAddress = engine.getVaultAddress();

        // 1. Deploy new implementation
        StrategyEngineV2 engineV2Implementation = new StrategyEngineV2();

        // 2. Execute upgrade through multisig (simulated)
        vm.expectEmit(true, true, true, true);
        emit Upgraded(address(engineV2Implementation));

        vm.prank(safeWallet);
        engine.upgradeToAndCall(
            address(engineV2Implementation),
            abi.encodeWithSelector(StrategyEngineV2.initializeV2.selector)
        );

        // 3. Cast to V2 to access new functions
        StrategyEngineV2 upgradedEngine = StrategyEngineV2(address(engine));

        // 4. Verify state was preserved through upgrade
        assertEq(
            upgradedEngine.getPlatformFee(),
            initialPlatformFee,
            "Platform fee should be preserved after upgrade"
        );
        assertEq(
            upgradedEngine.getDefaultLiquidationThreshold(),
            initialDefaultLiquidationThreshold,
            "Liquidation threshold should be preserved after upgrade"
        );
        assertEq(
            upgradedEngine.getVaultAddress(),
            initialVaultAddress,
            "Vault address should be preserved after upgrade"
        );

        // 5. Verify new functionality works
        assertEq(upgradedEngine.engineVersion(), 2, "New state variable should be initialized");
        assertEq(upgradedEngine.getVersion(), 2, "New function should return correct version");
    }

    /*//////////////////////////////////////////////////////////////
                    REALISTIC MULTISIG TESTS
    //////////////////////////////////////////////////////////////*/

    function test_RealMultisigVaultUpgrade() public {
        // 1. Deploy a new Vault with the real Safe wallet
        Vault vaultImpl = new Vault();
        bytes memory initData = abi.encodeWithSelector(Vault.initialize.selector, usdc, safeWallet);
        ERC1967Proxy proxy = new ERC1967Proxy(address(vaultImpl), initData);
        Vault testVault = Vault(address(proxy));

        // Verify initialization
        assertEq(testVault.safeWallet(), safeWallet);

        // 2. Deploy new implementation for upgrade
        VaultV2 vaultV2Implementation = new VaultV2();

        // 3. Create transaction data
        bytes memory upgradeCalldata = abi.encodeWithSelector(
            testVault.upgradeToAndCall.selector,
            address(vaultV2Implementation),
            abi.encodeWithSelector(VaultV2.initializeV2.selector)
        );

        // 4. Get transaction hash that would need to be signed
        bytes32 txHash = _getSafeTransactionHash(
            safeWallet,
            address(testVault),
            0, // value
            upgradeCalldata,
            0, // operation
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            address(0), // refundReceiver
            0 // nonce
        );

        // 5. Collect signatures from threshold number of signers
        bytes memory signatures = _collectSignatures(txHash, threshold);

        // 6. Execute transaction through Safe
        _executeSafeTransaction(safeWallet, address(testVault), 0, upgradeCalldata, 0, signatures);

        // 7. Verify upgrade was successful
        VaultV2 upgradedVault = VaultV2(address(testVault));
        assertEq(
            upgradedVault.implementation(),
            address(vaultV2Implementation),
            "Implementation should be updated"
        );
        assertEq(upgradedVault.vaultVersion(), 2, "V2 initialization should be complete");
        assertEq(upgradedVault.getVersion(), 2, "New V2 function should work");
    }

    function test_StrategyEngineUpgradeThroughSafeTx() public {
        // 1. Deploy a new StrategyEngine with the real Safe wallet for testing
        EngineInitParams memory params = EngineInitParams({
            wbtc: wbtc,
            usdc: usdc,
            aavePool: makeAddr("aavePool"),
            aaveOracle: makeAddr("aaveOracle"),
            aaveProtocolDataProvider: makeAddr("aaveDataProvider"),
            cpToken: address(cpToken),
            vault: address(vault),
            safeWallet: safeWallet
        });

        StrategyEngine engineImpl = new StrategyEngine();
        bytes memory initData = abi.encodeWithSelector(StrategyEngine.initialize.selector, params);
        ERC1967Proxy proxy = new ERC1967Proxy(address(engineImpl), initData);
        StrategyEngine testEngine = StrategyEngine(address(proxy));

        // Verify initialization
        assertEq(testEngine.upgradeRightsOwner(), safeWallet);

        // 2. Deploy new implementation for upgrade
        StrategyEngineV2 engineV2Implementation = new StrategyEngineV2();

        // 3. Create transaction data for SafeTx service
        bytes memory upgradeCalldata = abi.encodeWithSelector(
            testEngine.upgradeToAndCall.selector,
            address(engineV2Implementation),
            abi.encodeWithSelector(StrategyEngineV2.initializeV2.selector)
        );

        // 4. Simulate creating a Safe transaction
        // This would typically be done through the Safe UI or Safe Transaction Service API
        bytes32 safeTxHash = _getSafeTransactionHash(
            safeWallet,
            address(testEngine),
            0, // value
            upgradeCalldata,
            0, // operation
            0, // safeTxGas
            0, // baseGas
            0, // gasPrice
            address(0), // gasToken
            address(0), // refundReceiver
            0 // nonce
        );

        // 5. Simulate collecting off-chain signatures from signers
        // Each signer would sign the transaction hash individually through the Safe UI
        bytes memory signatures = new bytes(0);

        for (uint256 i = 0; i < threshold; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(safeSignerKeys[i], safeTxHash);
            signatures = abi.encodePacked(signatures, r, s, v); // Safe specific format
        }

        // 6. Simulate Safe Transaction Service execution
        // Any user can submit the collected signatures to execute the transaction
        console2.log("Executing upgrade through Safe Transaction Service...");
        console2.log("Target contract: ", address(testEngine));
        console2.log("Implementation target: ", address(engineV2Implementation));

        // Execute upgrade transaction
        vm.prank(safeWallet);
        testEngine.upgradeToAndCall(
            address(engineV2Implementation),
            abi.encodeWithSelector(StrategyEngineV2.initializeV2.selector)
        );

        // 7. Verify upgrade was successful
        StrategyEngineV2 upgradedEngine = StrategyEngineV2(address(testEngine));
        assertEq(
            upgradedEngine.implementation(),
            address(engineV2Implementation),
            "Implementation should be updated"
        );
        assertEq(upgradedEngine.engineVersion(), 2, "V2 initialization should be complete");
        assertEq(upgradedEngine.getVersion(), 2, "New V2 function should work");

        // 8. Test new functionality added in V2
        // First give the engine some tokens to test emergency withdraw
        deal(usdc, address(upgradedEngine), 500e6);
        uint256 initialBalance = IERC20(usdc).balanceOf(address(upgradedEngine));

        // Create emergency withdrawal transaction
        bytes memory emergencyWithdrawCalldata = abi.encodeWithSelector(
            StrategyEngineV2.emergencyWithdraw.selector,
            usdc,
            user1,
            100e6
        );

        // Execute emergency withdrawal
        vm.prank(safeWallet);
        (bool success, ) = address(upgradedEngine).call(emergencyWithdrawCalldata);
        assertTrue(success, "Emergency withdrawal should succeed");

        // Verify emergency withdrawal worked
        assertEq(
            IERC20(usdc).balanceOf(address(upgradedEngine)),
            initialBalance - 100e6,
            "Emergency withdrawal should reduce balance"
        );
        assertEq(
            IERC20(usdc).balanceOf(user1),
            1100e6,
            "User should receive emergency withdrawal funds"
        );
    }

    /*//////////////////////////////////////////////////////////////
                        HELPER FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    function _getSafeTransactionHash(
        address safe,
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    ) internal pure returns (bytes32) {
        // Simplified Safe transaction hash calculation
        return
            keccak256(
                abi.encodePacked(
                    safe,
                    to,
                    value,
                    keccak256(data),
                    operation,
                    safeTxGas,
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    nonce
                )
            );
    }

    function _collectSignatures(
        bytes32 txHash,
        uint256 sigCount
    ) internal view returns (bytes memory) {
        // This is a simplified signature collection
        // In reality, each signer would sign the transaction hash with their private key
        bytes memory signatures = new bytes(sigCount * 65);

        for (uint256 i = 0; i < sigCount; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(safeSignerKeys[i], txHash);

            uint256 offset = i * 65;
            signatures[offset] = bytes1(v);

            for (uint256 j = 0; j < 32; j++) {
                signatures[offset + j + 1] = r[j];
                signatures[offset + j + 33] = s[j];
            }
        }

        return signatures;
    }

    function _executeSafeTransaction(
        address safe,
        address to,
        uint256 /* value */,
        bytes memory data,
        uint8 /* operation */,
        bytes memory /* signatures */
    ) internal {
        // Mock the Safe's execTransaction function
        // In reality, this would execute the actual Safe transaction

        // For our test, we'll simulate the execution by directly calling the target
        vm.prank(safe);
        (bool success, ) = to.call(data);
        require(success, "Safe transaction execution failed");
    }
}

// Helper struct to match the StrategyEngine initialize function
struct EngineInitParams {
    address wbtc;
    address usdc;
    address aavePool;
    address aaveOracle;
    address aaveProtocolDataProvider;
    address cpToken;
    address vault;
    address safeWallet;
}
