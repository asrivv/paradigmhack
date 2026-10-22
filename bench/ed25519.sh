#!/bin/sh
# Measures LibEd25519 and challenge gas with forge's gas snapshots (local revm, standard EVM
# schedule). Prints the snapshot files the numbers in bench/ed25519.md come from.
set -eu
cd "$(dirname "$0")/../contracts"
forge test --match-test 'test_Gas' >/dev/null
cat snapshots/Ed25519.json
[ -f snapshots/Challenges.json ] && cat snapshots/Challenges.json
uname -mrs
sysctl -n machdep.cpu.brand_string 2>/dev/null || true
forge --version | head -1
