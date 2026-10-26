"""Run the fixture epoch end to end on the Moderato deployment with `cast`.

Steps, each a transaction whose receipt (block, gas used) is recorded:

1. registerEpoch: the fixture epoch with its withdrawal signed for the chain clock + 900 s.
2. admit: offchain/moderato replays the registration at the block time the chain recorded,
   deals and certifies the close. Before sending, the contract's frontierContext() must equal
   the crate's CloseContext byte for byte. Must land before the 60 s admission deadline.
3. finalize: after the 30 s challenge window (demo setting) closes.
4. claimWithdrawal: the payout to the withdrawal's destination; then a replay, which must fail
   with ClaimUnavailable, by eth_call.

    ETH_PRIVATE_KEY=$PRIVATE_KEY python3 -I script/moderato_epoch.py   # from contracts/

Writes deployments/moderato.epoch.json.
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# RPC_URL and DEPLOYMENT_PREFIX let the same script replay against a local node.
RPC = os.environ.get("RPC_URL", "https://rpc.moderato.tempo.xyz")
PREFIX = os.environ.get("DEPLOYMENT_PREFIX", "moderato")
ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "offchain" / "target" / "release" / "bajillion-moderato"
FIXTURES = ROOT / "contracts" / "test" / "fixtures"
OUT = ROOT / "deployments" / f"{PREFIX}.epoch.json"
ADMISSION = "(bytes32,bytes,uint64,bytes,bytes,(bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32,bytes32)[],bytes,bytes)"


def run(*args):
    out = subprocess.run(list(args), capture_output=True, text=True)
    if out.returncode != 0:
        sys.exit(f"{args[0]} {args[1]} failed: {out.stderr.strip()}")
    return out.stdout.strip()


def cast(command, *args):
    signer = ["--private-key", os.environ["ETH_PRIVATE_KEY"]] if command == "send" else []
    return run("cast", command, "--rpc-url", RPC, *signer, *args)


def send(label, settlement, signature, *args):
    receipt = json.loads(cast("send", "--json", settlement, signature, *args))
    if receipt.get("status") not in ("0x1", 1, "1"):
        sys.exit(f"{label} failed: {receipt.get('transactionHash')}")
    block = int(receipt["blockNumber"], 16)
    entry = {
        "method": label,
        "hash": receipt["transactionHash"],
        "block": block,
        "timestamp": int(cast("block", str(block), "--field", "timestamp")),
        "gasUsed": int(receipt["gasUsed"], 16),
    }
    print(f"{label}: block {block} gas {entry['gasUsed']}")
    return entry


def now():
    return int(cast("block", "latest", "--field", "timestamp"))


def committee():
    manifest = json.loads((FIXTURES / "manifest.json").read_text())
    points = []
    for member in manifest["bls"]["committee"]:
        raw = bytes.fromhex(member["public_key"]["eip2537"][2:])
        words = ["0x" + raw[i : i + 32].hex() for i in range(0, 256, 32)]
        points.append("(" + ",".join(words) + ")")
    return "[" + ",".join(points) + "]"


def main():
    if "ETH_PRIVATE_KEY" not in os.environ:
        sys.exit("set ETH_PRIVATE_KEY")
    settlement = json.loads((ROOT / "deployments" / f"{PREFIX}.plan.json").read_text())["settlement"]
    steps = []

    deadline = now() + 900
    epoch = json.loads(run(str(TOOL), "epoch", "--deadline", str(deadline)))
    steps.append(
        send(
            "registerEpoch",
            settlement,
            "registerEpoch(bytes,uint64,bytes,bytes,bytes)",
            epoch["epochContext"],
            "0",
            epoch["depositBatch"],
            epoch["withdrawalBatch"],
            "0x",
        )
    )
    registered_at = steps[-1]["timestamp"]

    close = json.loads(
        run(str(TOOL), "close", "--deadline", str(deadline), "--registered-at", str(registered_at))
    )
    onchain = cast("call", settlement, "frontierContext()(bytes)")
    if onchain.lower() != close["closeContext"].lower():
        sys.exit("frontierContext() differs from the crate's CloseContext")
    print("frontierContext() equals the crate's CloseContext")
    admission = (
        f"({close['header']},{close['rootBundle']},{close['withdrawalTotal']},{close['certificate']},"
        f"{close['signatureHint']},{committee()},{close['depositBatch']},{close['withdrawalBatch']})"
    )
    steps.append(send("admit", settlement, f"admit({ADMISSION})", admission))

    while now() <= close["finalizeAfter"]:
        time.sleep(2)
    steps.append(send("finalize", settlement, "finalize()"))
    steps.append(send("claimWithdrawal", settlement, "claimWithdrawal(uint64,bytes)", "0", close["payoutClaim"]))

    replay = subprocess.run(
        ["cast", "call", "--rpc-url", RPC, settlement, "claimWithdrawal(uint64,bytes)", "0", close["payoutClaim"]],
        capture_output=True,
        text=True,
    )
    # ClaimUnavailable() selector, from 0xf7eb630c.
    replay_rejected = replay.returncode != 0 and "0xf7eb630c" in (replay.stderr + replay.stdout)
    destination = "0x000000000000000000000000000000000000a11c"
    paid = int(cast("call", "0x20C0000000000000000000000000000000000000", "balanceOf(address)(uint256)", destination).split()[0])
    result = {
        "settlement": settlement,
        "withdrawalDeadline": deadline,
        "registeredAt": registered_at,
        "admissionDeadline": close["admissionDeadline"],
        "challengeDeadline": close["challengeDeadline"],
        "header": close["header"],
        "steps": steps,
        "destinationBalance": paid,
        "replayRejected": replay_rejected,
        "replayError": (replay.stderr or replay.stdout).strip()[-200:],
    }
    OUT.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps({k: result[k] for k in ("destinationBalance", "replayRejected")}))


if __name__ == "__main__":
    main()
