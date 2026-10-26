"""Broadcast deployments/moderato.plan.json to Tempo Moderato with `cast send`, in order.

DeployModerato.s.sol writes the plan: one CREATE per library (1,000,000-run artifacts, linked
at the addresses these CREATEs produce), the pathUSD approval, then the settlement CREATE.
`cast send` takes its gas from the node's estimate, so Tempo's gas schedule applies. The key
comes from ETH_PRIVATE_KEY and is never printed. Refuses to start unless the deployer's nonce is
the plan's start nonce, so library addresses match their links.

    ETH_PRIVATE_KEY=$PRIVATE_KEY python3 -I script/broadcast_plan.py   # from contracts/

Writes deployments/moderato.receipts.json: per transaction, hash, block, gas used and
created address.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

RPC = "https://rpc.moderato.tempo.xyz"
ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "deployments" / "moderato.plan.json"
RECEIPTS = ROOT / "deployments" / "moderato.receipts.json"


def cast(*args):
    out = subprocess.run(["cast", *args, "--rpc-url", RPC], capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"cast {args[0]} failed: {out.stderr.strip()}")
    return out.stdout.strip()


def main():
    if "ETH_PRIVATE_KEY" not in os.environ:
        sys.exit("set ETH_PRIVATE_KEY")
    plan = json.loads(PLAN.read_text())
    txs = plan["transactions"]
    if isinstance(txs, str):
        txs = json.loads(txs)
    nonce = int(cast("nonce", plan["deployer"]))
    if nonce != int(plan["startNonce"]):
        sys.exit(f"deployer nonce {nonce} != plan start nonce {plan['startNonce']}; regenerate the plan")
    receipts = []
    for key in sorted(txs):
        data = txs[key]
        if key == f"{len(txs) - 2:02d}":
            args = ["send", plan["pathUSD"], data]
            label = "approve pathUSD"
        else:
            args = ["send", "--create", data]
            label = "create"
        receipt = json.loads(cast(*args, "--json"))
        if receipt.get("status") not in ("0x1", 1, "1"):
            sys.exit(f"tx {key} ({label}) failed: {receipt.get('transactionHash')}")
        entry = {
            "index": key,
            "label": label,
            "hash": receipt["transactionHash"],
            "block": int(receipt["blockNumber"], 16),
            "gasUsed": int(receipt["gasUsed"], 16),
            "contractAddress": receipt.get("contractAddress"),
        }
        receipts.append(entry)
        print(f"{key} {label}: block {entry['block']} gas {entry['gasUsed']} {entry['contractAddress'] or ''}")
    RECEIPTS.write_text(json.dumps(receipts, indent=1) + "\n")


if __name__ == "__main__":
    main()
