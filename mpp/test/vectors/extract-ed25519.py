"""Writes ed25519-zip215.json from the pinned crate's own test vectors.

Reads cryptography/curve25519/src/test/vectors.rs from the commonware submodule and extracts
the Wycheproof Ed25519 vectors with the crate's ZIP215 verdicts, plus its ZIP215 points.
Run from anywhere (needs the contracts/lib/commonware submodule):

    python3 -I mpp/test/vectors/extract-ed25519.py
"""

import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SOURCE = HERE.parents[2] / "contracts/lib/commonware/cryptography/curve25519/src/test/vectors.rs"
OUTPUT = HERE / "ed25519-zip215.json"


def hexes(block):
    # Long values are split across string literals; only the first carries the 0x prefix.
    return "".join(re.findall(r'"(?:0x)?([0-9a-fA-F]*)"', block))


def main(source, output):
    src = Path(source).read_text()
    w = src[src.index("pub(super) const WYCHEPROOF_ED25519"):src.index("pub(super) const RFC7748_X25519:")]
    vectors = []
    for m in re.finditer(r"WycheproofEd25519Vector \{(.*?)valid_zip215: (true|false),\s*\}", w, re.S):
        body = m.group(1)
        tc = int(re.search(r"tc_id: (\d+)", body).group(1))
        pk = hexes(re.search(r"public_key: commonware_formatting::hex!\((.*?)\)", body, re.S).group(1))
        msg = hexes(re.search(r"message: &commonware_formatting::hex!\((.*?)\)", body, re.S).group(1))
        sig = hexes(re.search(r"signature: &commonware_formatting::hex!\((.*?)\)", body, re.S).group(1))
        vectors.append({
            "tcId": tc,
            "publicKey": "0x" + pk,
            "message": "0x" + msg,
            "signature": "0x" + sig,
            "validZip215": m.group(2) == "true",
        })
    z = src[src.index("pub(super) const ZIP215_POINTS"):]
    z = z[:z.index("\n];")]
    points = ["0x" + p for p in re.findall(r'"0x([0-9a-fA-F]{64})"', z)]
    assert len(points) == 14, len(points)
    assert len(vectors) == 151, len(vectors)
    with open(output, "w") as out:
        json.dump({
            "source": "commonwarexyz/monorepo@dd6d60cb44fb3dc05cee1efa06d957ce30df1340 cryptography/curve25519/src/test/vectors.rs",
            "note": "validZip215 is the crate's verdict for VerifyingKey::verify_raw (unframed message).",
            "wycheproof": vectors,
            "zip215Points": points,
        }, out, indent=1)
    print(len(vectors), sum(v["validZip215"] for v in vectors))


if __name__ == "__main__":
    main(*(sys.argv[1:3] if len(sys.argv) >= 3 else (SOURCE, OUTPUT)))
