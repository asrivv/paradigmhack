# Spare Change

An independent integration of Bajillion, the clearing protocol designed by Patrick O'Grady at Commonware ([commonware.xyz/blogs/clearing](https://commonware.xyz/blogs/clearing), crate `commonware-clearing`). The protocol and the clearing crate are theirs. The Tempo settlement contract, the MPP payment method, the demo and the adversarial test suite are ours.

Agents now pay for software directly, a few cents per call. [MPP](https://mpp.dev/overview), the Machine Payments Protocol from Tempo and Stripe, handles this well. Its sessions are payment channels, though, and a channel runs between one payer and one vendor. An agent working with thirty vendors keeps thirty funded channels, and most of that capital sits idle.

[Bajillion](https://commonware.xyz/blogs/clearing) is a clearing protocol designed by Patrick O'Grady at Commonware. It nets many-to-many payments into a single commitment per round, about 100 bytes, certified by a small committee. An agent deposits once and can pay any participant. The protocol relies on receipts rather than trust in the operator. Every payment produces a signed receipt, and every commitment waits out a public challenge window before funds move. A receipt that contradicts a commitment is proof of fraud. Submitting it voids the round and halts the system, and every account can then withdraw its last confirmed balance without the operator.

Commonware's [`commonware-clearing`](https://github.com/commonwarexyz/monorepo/tree/dd6d60cb44fb3dc05cee1efa06d957ce30df1340/clearing) crate implements the protocol and deliberately leaves settlement to the application. I built that layer on [Tempo](https://docs.tempo.xyz), which runs on Commonware's own consensus:

- a [contract](contracts/src) that holds deposits, verifies committee certificates, adjudicates challenges and pays out
- an [MPP payment method](mpp), so a service already on MPP can accept Bajillion

To check conformance, I ran 1,000 randomized operation sequences through the contract and through Commonware's reference implementation in parallel and compared the full state after every step. They matched in every run ([harness](contracts/test/Differential.t.sol), [reference oracle](offchain/oracle)).

The contract is [live on Tempo's testnet](https://explore.moderato.tempo.xyz/address/0x78F12F6Fbc6d5b5BdC249cb59dAe541fDBee81a9), with one full round run end to end.

## Verify it

- **Deployed contract:** [`0x78F1…81a9`](https://explore.moderato.tempo.xyz/address/0x78F12F6Fbc6d5b5BdC249cb59dAe541fDBee81a9) on Tempo Moderato, block 41,323,147. Full record in [`deployments/moderato.json`](deployments/moderato.json).
- **One full round on chain:** [register](https://explore.moderato.tempo.xyz/tx/0x3292504b6f33869afccca5c543625ee9aad90de7ed98aa883ac569a2ab9f6d29), [certified close](https://explore.moderato.tempo.xyz/tx/0x2caa524d5d83513a1df4d20467a812ed2b56d80fee1cc08ca9f77d40d8eb1bbb), [finalize](https://explore.moderato.tempo.xyz/tx/0x56563d73484883696c492760eb75d9dc9271b2c36122809a6fb5d480b4af589f), [payout](https://explore.moderato.tempo.xyz/tx/0xd1015b707776991e066f13f368b10b0bcd53451ad47995751b5f949d338b8808).
- **Gas:** [`bench/gas.md`](bench/gas.md), measured Tempo gas beside a local run on the Ethereum schedule, per transaction.
- **Design and trust assumptions:** [`docs/DESIGN.md`](docs/DESIGN.md).
- **Upstream pin:** [`commonwarexyz/monorepo@dd6d60cb`](https://github.com/commonwarexyz/monorepo/tree/dd6d60cb44fb3dc05cee1efa06d957ce30df1340).
