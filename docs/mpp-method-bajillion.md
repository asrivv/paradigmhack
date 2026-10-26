# Bajillion Charge Intent for HTTP Payment Authentication

This document follows the structure of `draft-tempo-charge-00` and implements the `charge`
intent of `draft-payment-intent-charge-00` within the `Payment` HTTP authentication scheme of
`draft-httpauth-payment-01`. The reference implementation is [`mpp/`](../mpp).

The key words MUST, MUST NOT, REQUIRED, SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are
to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in
all capitals.

## Abstract

Bajillion is Commonware's clearing protocol (`commonware-clearing`). Payers deposit once into a
settlement contract on Tempo. An off-chain operator acknowledges payments between deposits, and
epoch closes certified by a validator committee settle the net result on chain. This document
defines the `bajillion` payment method for the `charge` intent. The client proves payment with
an `EntryReceipt`: the payer's signed cumulative vector endpoint, the operator's
countersignature, and a Merkle opening of the entry that credits the server.

## 1. Introduction

A Tempo charge moves tokens on chain for every request. A Bajillion charge moves none. The
payer raises its cumulative credit to the recipient inside the operator's current epoch, the
operator countersigns the new endpoint, and the server checks the countersigned receipt. The
deposit, epoch close, challenge window and withdrawal happen on Tempo independently of any HTTP
exchange.

```
Client                      Operator                    Server
  |  (1) GET /resource         |                           |
  |------------------------------------------------------->|
  |  (2) 402, method="bajillion", intent="charge"          |
  |<-------------------------------------------------------|
  |  (3) POST accept-send      |                           |
  |      SendAuthorization     |                           |
  |--------------------------->|                           |
  |  (4) VectorAck + opening   |                           |
  |<---------------------------|                           |
  |  (5) Authorization: Payment <EntryReceipt>             |
  |------------------------------------------------------->|
  |                            |   (6) verify, retain      |
  |  (7) 200 OK + Payment-Receipt                          |
  |<-------------------------------------------------------|
```

All byte layouts are those of `commonwarexyz/monorepo` at
`dd6d60cb44fb3dc05cee1efa06d957ce30df1340` with `D = SHA-256` and `P = StrictVerifyingKey`
(ed25519). [`protocol-notes.md`](protocol-notes.md) gives the conventions. Paths below are
relative to `clearing/src/bajillion/` at that commit.

## 2. Terminology

Epoch context
: The operator's registered `EpochContext` (264 bytes, `transition.rs:690-704`). Its first 72
bytes are the `PaymentContext` `anchor || epoch || operator` that every acknowledgment binds.

Out-vector
: A payer's epoch-cumulative list of `OutEntry { recipient, cumulative, count }`, strictly
sorted by recipient bytes (`vector.rs:21-50`), committed as an exact-length vector with the
`OutEntry` domains (`commitment.rs:20-21`).

Entry receipt
: `EntryReceipt { ack, recipient, cumulative, count, opening }` (`payment.rs:460-525`).

Edge
: One (epoch anchor, payer, recipient) triple.

## 3. Method Identifier

`bajillion`

## 4. Request Schema

The `request` auth-param is the base64url JCS encoding of:

| Field | Type | Required | Description |
|---|---|---|---|
| `amount` | string | REQUIRED | Credit required, in base units of `currency`: a positive base-10 integer no greater than 2^64 - 1 (crate amounts are `u64`) |
| `currency` | string | REQUIRED | The deployment's settlement token, a TIP-20 address |
| `recipient` | string | REQUIRED | The clearing account to credit: a 32-byte ed25519 strict verifying key, `0x` lowercase hex |
| `description` | string | OPTIONAL | Human-readable description |
| `externalId` | string | OPTIONAL | Merchant reference |
| `methodDetails.epochContext` | string | REQUIRED | The operator's live `EpochContext`, 264 bytes, `0x` lowercase hex |

`methodDetails.epochContext` is REQUIRED in every challenge. A server MAY resolve it when it
issues each challenge.

Example:

```json
{
  "amount": "10000",
  "currency": "0x20c0000000000000000000000000000000000000",
  "methodDetails": {
    "epochContext": "0x7675afbcf6838ca4595b016f180fe037cd3d84d5218b931384a899fc5f042a7d0000000000000001f0a7d3368f79ddfccab74add41b08fa03481bdbd1b1ef98c7856c9d816f7a367ab3c…"
  },
  "recipient": "0xf4218e0a231d995b7f3edde2168be1c19da77aef26e63e87265a5a782ffe2b7b"
}
```

Challenge expiry is the `expires` auth-param. Servers SHOULD set it no later than the
epoch's expected cut, because the operator answers a send under a cut epoch with a corrective
report rather than an acknowledgment.

## 5. Credential Schema

### 5.1 Credential Structure

| Field | Type | Required | Description |
|---|---|---|---|
| `challenge` | object | REQUIRED | Echo of the challenge |
| `payload` | object | REQUIRED | Payload below |
| `source` | string | OPTIONAL | Not used by this method |

### 5.2 Receipt Payload (`type="receipt"`)

| Field | Type | Required | Description |
|---|---|---|---|
| `type` | string | REQUIRED | `"receipt"` |
| `receipt` | string | REQUIRED | The `EntryReceipt`, crate-encoded, `0x` hex |

The encoding, for one entry of an `n`-entry vector with `k` siblings:

| Offset | Size | Field |
|---|---|---|
| 0 | 32 | `ack.body.anchor` |
| 32 | 8 | `ack.body.epoch` (u64 BE) |
| 40 | 32 | `ack.body.payer` (strict ed25519 key) |
| 72 | 8 | `ack.body.seq` (u64 BE) |
| 80 | 8 | `ack.body.cumulative_debit` (u64 BE) |
| 88 | 32 | `ack.body.send_root` |
| 120 | 32 | `ack.predecessor` |
| 152 | 64 | `ack.payer_signature` |
| 216 | 64 | `ack.operator_signature` |
| 280 | 32 | `recipient` (strict ed25519 key) |
| 312 | 8 | `cumulative` (u64 BE) |
| 320 | 8 | `count` (u64 BE) |
| 328 | 4 | `opening.position` (u32 BE) |
| 332 | 4 | `opening.proof.leaf_count` (u32 BE, `n`) |
| 336 | 1-5 | `k`, canonical LEB128 varint, at most 32 |
| … | 32·k | siblings, leaf level first |

A one-entry receipt is 337 bytes. Decoding MUST reject trailing bytes, non-canonical varints,
`k > 32`, `n > 2^24`, `position >= n`, and keys that are not canonical, non-identity,
prime-order points (`signing.rs:457-470`).

## 6. Verification Procedure

In addition to the checks of `draft-httpauth-payment-01` (challenge binding, expiry, payload
schema), servers MUST:

1. Decode `methodDetails.epochContext` from the echoed challenge and recompute its anchor:
   `SHA256("_COMMONWARE_CLEARING_EPOCH_ANCHOR" || deployment || deposit_root ||
   withdrawal_root || u64 epoch || operator || limits || committee)` (`transition.rs:533-551`).
   It MUST equal the context's anchor, and the context's operator MUST be the operator the
   server trusts.
2. Require `recipient` in the echoed request to be the server's own account.
3. Decode the receipt (Section 5.2).
4. `ack.body.anchor` and `ack.body.epoch` MUST equal the context's (`WrongContext`).
5. Let `message = body || predecessor` (152 bytes, `payment.rs:188-196`). The payer signature
   MUST verify for `ack.body.payer` over `union_unique("_COMMONWARE_CLEARING_VECTOR_SEND",
   message)` (`InvalidPayerSignature`). `union_unique(ns, m)` is `varint(len(ns)) || ns || m`.
6. The operator signature MUST verify for the context's operator over
   `union_unique("_COMMONWARE_CLEARING_VECTOR_ACK", message)` (`InvalidOperatorSignature`).
7. `cumulative > 0`, `count > 0` and `cumulative >= count` (`InfeasibleEntry`).
8. Reconstruct the root (`commitment.rs:654-666`, `storage/src/bmt/mod.rs`):

   ```
   leaf  = SHA256("_COMMONWARE_CLEARING_OUT_ENTRY_LEAF" || u32 n || u32 position
                  || u64 48 || recipient || u64 cumulative || u64 count)
   node  = SHA256(u32 position || leaf)
   for each level while width > 1:
       odd position:            node = SHA256(sibling || node)
       even, position+1 < width: node = SHA256(node || sibling)
       even, last node:          node = SHA256(node || node)      (consumes no sibling)
       position /= 2; width = ceil(width / 2)
   every sibling MUST be consumed
   root  = SHA256("_COMMONWARE_CLEARING_OUT_ENTRY_ROOT" || u32 n || SHA256(u32 n || node))
   ```

   `root` MUST equal `ack.body.send_root` (`InvalidEntryOpening`).
9. The receipt's `recipient` MUST equal the server's account.
10. Let `(c0, n0)` be the `(cumulative, count)` last accepted on this edge, `(0, 0)` if none.
    The server MUST require `count > n0` and `cumulative > c0`, and otherwise reject the credential
    as consumed. It MUST require `cumulative - c0 >= amount` (`payment-insufficient`).
11. Atomically replace the edge watermark with `(cumulative, count)`, under the same conditions
    as step 10.

Ed25519 verification MUST follow the crate's ZIP215 rules (`signing.rs:1-24`): `A` and `R` MAY
be non-canonical point encodings, `s` MUST be canonical (`s < L`), the challenge scalar hashes
the exact `R`, `A` and message bytes, and the equation is cofactored, `[8](sB - R - kA) = 0`.
The reference implementation reproduces the crate's verdicts for all 151 of its Wycheproof
vectors.

Steps 4 to 8 are `EntryReceipt::verify::<Sha256>` exactly. An implementation MAY call the crate
instead.

### 6.1 Settlement

Settlement is deferred and does not involve the server. The receipt binds the operator to the
payer's endpoint. The epoch close later commits the payer's terminal vector, and validators
certify it on Tempo. Before verified evidence is acknowledged, servers MUST retain it, because
it is what lets the recipient challenge a close that omits or understates the credit
(`challenge.rs`, `HigherAckEntry`). The reference implementation hands each receipt to an
`onReceipt` hook before it acknowledges the payment. If retention fails, it refuses the payment
and rolls the watermark back.

### 6.2 Operator Interaction (client side)

The client signs `SendAuthorization { body, predecessor, payer_signature }` for its next
endpoint: `seq` increases by one, `cumulative_debit` increases by `amount`, and the recipient's
entry rises by `amount`, with one more count. `predecessor` is the root of the payer's last
vector in the preceding epoch, or the empty out-entry root. The client submits that send with
its delta list (the reference terminal's `AcceptSendRequest`). The reference implementation
binds that body to `POST <operatorUrl>/accept-send` with `application/octet-stream` bodies, and
the response is the terminal's `AcceptSendResponse`. Before sending the credential, the client
MUST check that the acknowledgment covers exactly the body it signed and that the receipt
passes Section 6.

## 7. Receipt

| Field | Type | Description |
|---|---|---|
| `method` | string | `"bajillion"` |
| `reference` | string | `0x` hex SHA-256 of the encoded `EntryReceipt` |
| `status` | string | `"success"` |
| `timestamp` | string | RFC 3339 verification time |
| `externalId` | string | OPTIONAL, echoed from the request |
| `payer` | string | Payer account, `0x` hex |
| `epoch` | string | Epoch number |
| `seq` | string | Acknowledged batch sequence |
| `cumulative` | string | Edge cumulative after this payment |

## 8. Security Considerations

### 8.1 Replay and Single Use

The signed message carries no challenge identifier, because the crate format fixes it. Single
use is therefore per edge: each acceptance raises a monotone watermark, and a receipt that does
not raise it is rejected. Servers MUST keep watermarks in an atomic store shared by every
instance that credits the same account. Otherwise one receipt can pay once per instance.

### 8.2 Credential Theft

A receipt is a bearer credential for the server named in it. Anyone holding it can present it
to that server against another challenge, and the first presentation wins. TLS is REQUIRED, as
in the core specification.

### 8.3 Operator Trust and Finality

An acknowledgment is a promise from the operator, not settled funds. An operator that
countersigns endpoints and then closes the epoch without them can be challenged on chain. A
proven challenge hard-faults the deployment, and balances are recovered from the last finalized
state (`settlement.rs:1574-1614`). The pinned crate has no operator bond (see
[`protocol-notes.md` §6](protocol-notes.md)). Servers SHOULD size the credit they extend per
epoch to their tolerance for that outcome.

### 8.4 Epoch Context Provenance

Step 1 shows that the context is internally consistent, not that it was registered on chain. A
server MUST take its epoch context and operator key from a source it trusts. Before it releases
an acknowledgment, the operator must wait until the anchor is registered (`payment.rs:48-56`).

### 8.5 Payer Over-Debit

The payer's debit endpoint can exceed its balance. The operator, not the server, enforces
solvency. A close carries only debits its state root covers.

### 8.6 Client Amount Verification

Before signing, clients MUST check `amount`, `currency`, `recipient`, and that the context's
operator is the one they deposited with.

## 9. IANA Considerations

This document would register `bajillion` in the HTTP Payment Methods registry for the `charge`
intent.
