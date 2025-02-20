-include .env

.PHONY: upgrade-dry upgrade

SCRIPT_STRATEGY_ENGINE_PATH=script/upgrade/UpgradeStrategyEngine.s.sol:UpgradeStrategyEngine
SCRIPT_MULTISIG_PATH=script/upgrade/UpgradeMultiSig.s.sol:UpgradeMultiSig
SCRIPT_SIGNER_MANAGER_PATH=script/upgrade/UpgradeSignerManager.s.sol:UpgradeSignerManager
SCRIPT_ADD_SIGNER_PATH=script/control/AddSigner.s.sol:AddSigner

upgrade-dry:
	forge script ${SCRIPT_SIGNER_MANAGER_PATH} -vvvv \
		--rpc-url ${RPC_URL} \
		--sender ${SENDER} \
		--private-key ${PRIVATE_KEY} \
		--sig "run()"

upgrade:
	forge script ${SCRIPT_SIGNER_MANAGER_PATH} \
		--rpc-url ${RPC_URL} \
		--broadcast \
		--verify \
		--sender ${SENDER} \
		--private-key ${PRIVATE_KEY} \
		--sig "run()"

add-signer:
	forge script ${SCRIPT_ADD_SIGNER_PATH} -vvvv \
		--rpc-url ${RPC_URL} \
		--sender ${SENDER} \
		--private-key ${PRIVATE_KEY} \
		--sig "run()"
