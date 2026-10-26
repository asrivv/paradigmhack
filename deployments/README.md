# Deployments

## Tempo Moderato (chain 42431)

`moderato.json` records the live deployment: settlement address and block, deployer, the commit
it was built from, the library addresses, the demo settings, and the fixture epoch that ran on it.
The settings are demo settings, not production ones: the 30-second challenge window exists so the
demo finalizes in about two minutes.

Reproduce from a clean checkout, with `PRIVATE_KEY` in `../.env` (gitignored) and the deployer
funded with pathUSD (`cast rpc tempo_fundAddress <address> --rpc-url https://rpc.moderato.tempo.xyz`):

```sh
(cd offchain && cargo build --release --locked -p bajillion-moderato)
cd contracts && forge build && set -a && . ../.env && set +a
forge script script/DeployModerato.s.sol --rpc-url moderato                  # writes moderato.plan.json
ETH_PRIVATE_KEY=$PRIVATE_KEY python3 -I script/broadcast_plan.py              # 13 transactions
forge script script/DeployModerato.s.sol --rpc-url moderato --sig "verify()"  # on-chain code check
ETH_PRIVATE_KEY=$PRIVATE_KEY python3 -I script/moderato_epoch.py              # fixture epoch
```

The plan is broadcast with `cast send` rather than `forge script --broadcast` because forge 1.5.1
cannot simulate Tempo's native TIP-20 precompiles (pathUSD reverts with `OpcodeNotFound`) and
prices state creation by Ethereum's schedule. `cast` uses the node's gas estimate.

Files: `moderato.plan.json` (the exact transactions), `moderato.receipts.json` (deployment
receipts), `moderato.epoch.json` (epoch receipts and deadlines). Gas analysis: `bench/gas.md`.
