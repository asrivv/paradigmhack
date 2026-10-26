# Gas: Tempo Moderato against the standard EVM schedule

Every number below is a `gasUsed` from a transaction receipt. Both columns run the same
transactions with the same bytes: the deployment plan from `contracts/script/DeployModerato.s.sol`
(libraries from their 1,000,000-run artifacts, linked by hand, and the 200-run settlement) and the
fixture epoch built by `offchain/moderato` (the crate fixture epoch rebuilt for the chain's clock,
certified by 3 of the 4 fixture validators).

- **Tempo Moderato**: chain 42431, `https://rpc.moderato.tempo.xyz`, deployer
  `0xC1aE0eBb1f6fcF61FfA4eA88AC5ea719B8AF4099`, 26 October 2026. Receipts: `deployments/moderato.receipts.json`
  (deployment) and `deployments/moderato.epoch.json` (epoch). Scripts:
  `contracts/script/broadcast_plan.py`, `contracts/script/moderato_epoch.py`.
- **Local**: anvil (foundry 1.5.1) with chain id 42431 and the standard Ethereum gas schedule,
  pathUSD replaced by `MockTIP20` at the same address. Reproduce with `sh bench/gas.sh`; receipts in
  `bench/data/`. Machine: Apple M4 Pro, macOS 15.1.

Tempo's published schedule (tempo.xyz developer docs, EVM compatibility) charges 250,000 gas for a
new storage slot (20,000 on Ethereum), 250,000 for creating an account, and 1,000 per byte of
deployed code (200 on Ethereum), and caps a transaction at 30M gas. Those three prices explain the
ratios: computation (BLS pairings, Ed25519, SHA-256 proofs) costs the same on both.

## Deployment

| Transaction | Initcode or calldata bytes | Local gas | Moderato gas | Ratio | Moderato block |
|---|---|---|---|---|---|
| Ed25519Verifier | 8,302 | 1,833,879 | 9,169,479 | 5.00 | 41,323,093 |
| CertificateVerifier | 5,983 | 1,336,461 | 6,566,861 | 4.91 | 41,323,097 |
| PayoutVerifier | 6,225 | 1,389,348 | 6,813,348 | 4.90 | 41,323,102 |
| AdmissionVerifier | 7,579 | 1,672,608 | 8,179,808 | 4.89 | 41,323,107 |
| WithdrawalCodec | 5,010 | 1,125,510 | 5,577,510 | 4.96 | 41,323,112 |
| StateVerifier | 7,892 | 1,749,138 | 8,506,738 | 4.86 | 41,323,116 |
| BajillionChallenge | 16,136 | 3,512,165 | 16,863,425 | 4.80 | 41,323,118 |
| BajillionWithdrawals | 9,415 | 2,070,574 | 10,045,022 | 4.85 | 41,323,123 |
| BajillionClaims | 4,426 | 997,964 | 4,981,164 | 4.99 | 41,323,128 |
| BajillionLiveness | 1,290 | 324,963 | 1,800,963 | 5.54 | 41,323,133 |
| BajillionRecovery | 7,942 | 1,750,681 | 8,546,705 | 4.88 | 41,323,137 |
| pathUSD approve | 68 | 44,015 | 277,918 | 6.31 | 41,323,142 |
| BajillionSettlement (200 runs) | 32,215 | 6,471,831 | 28,057,414 | 4.34 | 41,323,147 |
| **Total** | | **24,279,137** | **115,386,355** | **4.75** | |

The settlement deployment uses 28,057,414 gas, 93.5 percent of Tempo's 30M transaction
cap: about 24.4M is the 1,000-per-byte code deposit for its 24,385 bytes, and the rest is the
constructor (four proof-of-possession pairings and the initial storage). On Tempo, code size is a
deployment constraint in its own right, not only EIP-170: about 1.9M gas of headroom remains.

## Fixture epoch

| Method | Local gas | Moderato gas | Ratio | Moderato block | Transaction |
|---|---|---|---|---|---|
| `registerEpoch` | 1,481,379 | 3,779,029 | 2.55 | 41,323,388 | `0x3292504b6f33869afccca5c543625ee9aad90de7ed98aa883ac569a2ab9f6d29` |
| `admit` | 483,985 | 2,328,112 | 4.81 | 41,323,394 | `0x2caa524d5d83513a1df4d20467a812ed2b56d80fee1cc08ca9f77d40d8eb1bbb` |
| `finalize` | 176,756 | 869,356 | 4.92 | 41,323,543 | `0x56563d73484883696c492760eb75d9dc9271b2c36122809a6fb5d480b4af589f` |
| `claimWithdrawal` | 127,756 | 356,117 | 2.79 | 41,323,547 | `0xd1015b707776991e066f13f368b10b0bcd53451ad47995751b5f949d338b8808` |

What each call did on Moderato:

- `registerEpoch`: registered epoch 1 with one operator-carried withdrawal, which costs one
  ZIP215 Ed25519 verification and one strict-key check (about 1.3M of computation on both
  schedules), and wrote the epoch record and the withdrawal bookkeeping into new slots.
- `admit`: verified the 3-of-4 BLS12-381 MinSig certificate (one pairing) and the boundary roots,
  and filled the admission half of the epoch record, again in new slots.
- `finalize`: moved the certified withdrawal total (10 units) into the claim reserve, wrote the
  finalized heads, and recorded the trailing commit location as claimed.
- `claimWithdrawal`: verified the payout's MMR opening with SHA-256 and paid 10 base units of
  pathUSD to `0x…a11c`, a new account on Tempo. A replay was rejected with `ClaimUnavailable`
  (checked by `eth_call`, no transaction).

The contract's `frontierContext()` after registration equalled the crate's `CloseContext` byte for
byte (`moderato_epoch.py` refuses to admit otherwise), so the header the committee certified is the
one the contract recomputed.

## Not measured on Moderato

`deposit`, `queueWithdrawal`, `challenge` and the terminal-settlement methods did not run on the
demo deployment: a deposit that no registration pulls expires after 300 seconds and hard-faults
the deployment, and a proven challenge does so by design. Their local costs are in the forge gas
snapshots (`contracts/snapshots/`), with one caveat: forge's test linker sometimes links the 200-run
library copies into tests that embed the settlement, so those snapshots can overstate the
production libraries' cost (in-test Ed25519 verification measured 949,348 and 1,154,164 gas in two
builds). The numbers in this file do not depend on forge's linker.
