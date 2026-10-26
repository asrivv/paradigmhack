#!/bin/sh
# Reproduce the "local" column of bench/gas.md: replay the Moderato deployment plan and the
# fixture epoch, byte for byte, against a local anvil node with the standard Ethereum gas
# schedule. pathUSD is replaced by the test suite's MockTIP20 at the same address.
#
# Needs PRIVATE_KEY in ../.env (the deployer; the plan links libraries at its CREATE addresses),
# foundry (anvil, cast, forge) and the bajillion-moderato binary:
#   (cd offchain && cargo build --release --locked -p bajillion-moderato)
# Run from the repository root: sh bench/gas.sh
set -eu
ROOT=$(cd "$(dirname "$0")/.." && pwd)
L=http://127.0.0.1:8545
PATH_USD=0x20C0000000000000000000000000000000000000
set -a; . "$ROOT/.env"; set +a
DEPLOYER=$(cast wallet address --private-key "$PRIVATE_KEY")

anvil --chain-id 42431 --block-time 1 --port 8545 --gas-limit 500000000 --code-size-limit 24576 >/dev/null 2>&1 &
ANVIL=$!
trap 'kill $ANVIL' EXIT
sleep 3

cd "$ROOT/contracts"
cast rpc anvil_setCode $PATH_USD "$(forge inspect MockTIP20 deployedBytecode)" --rpc-url $L >/dev/null
cast rpc anvil_setBalance "$DEPLOYER" 0x56BC75E2D63100000 --rpc-url $L >/dev/null
cast rpc anvil_impersonateAccount "$DEPLOYER" --rpc-url $L >/dev/null
cast send --unlocked --from "$DEPLOYER" $PATH_USD "mint(address,uint256)" "$DEPLOYER" 1000000000 --rpc-url $L >/dev/null
cast rpc anvil_stopImpersonatingAccount "$DEPLOYER" --rpc-url $L >/dev/null

PLAN_FILE=../deployments/local.plan.json forge script script/DeployModerato.s.sol --rpc-url $L >/dev/null
RPC_URL=$L DEPLOYMENT_PREFIX=local ETH_PRIVATE_KEY=$PRIVATE_KEY python3 -I script/broadcast_plan.py
PLAN_FILE=../deployments/local.plan.json forge script script/DeployModerato.s.sol --rpc-url $L --sig "verify()" | grep verified
RPC_URL=$L DEPLOYMENT_PREFIX=local ETH_PRIVATE_KEY=$PRIVATE_KEY python3 -I script/moderato_epoch.py

mkdir -p "$ROOT/bench/data"
mv "$ROOT/deployments/local.receipts.json" "$ROOT/bench/data/anvil.receipts.json"
mv "$ROOT/deployments/local.epoch.json" "$ROOT/bench/data/anvil.epoch.json"
rm -f "$ROOT/deployments/local.plan.json"
