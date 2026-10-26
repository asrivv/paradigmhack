# Bajillion payment method for MPP

A `bajillion` payment method for [`mppx`](https://github.com/wevm/mppx), the Machine Payments
Protocol TypeScript SDK, used unmodified. An agent deposits once into a Bajillion deployment on
Tempo and pays any number of MPP services from that deposit. Each payment is proven by an
`EntryReceipt` from Commonware's `commonware-clearing` crate: the payer's signed vector
endpoint, the operator's countersignature, and a BMT opening of the recipient's entry.

The wire format is specified in [`docs/mpp-method-bajillion.md`](../docs/mpp-method-bajillion.md).

## Adopting it in an existing server

Add one entry to the `methods` you already pass to `Mppx.create`:

```ts
import { Mppx, tempo } from 'mppx/server'
import { bajillion } from '@paradigmhack/mpp-bajillion/server'

const mppx = Mppx.create({
  methods: [
    tempo({ recipient: '0x742d35Cc6634c0532925a3b844bC9e7595F8fE00' }),
    bajillion({ currency, epochContext, operator, recipient, onReceipt: (r) => watcher.store(r.encoded) }), // ← the one line
  ],
  secretKey: process.env.MPP_SECRET_KEY!,
})

// Charge with it alone, or offer it next to tempo on the same route.
const pay = mppx.compose([mppx.tempo.charge, { amount: '0.01' }], [mppx.bajillion.charge, { amount: '10000' }])
```

| Parameter | Meaning |
|---|---|
| `currency` | Settlement token of the deployment (TIP-20 address). Amounts are its base units. |
| `epochContext` | The operator's live `EpochContext` (264 bytes, `0x` hex), or a function returning it for each challenge. |
| `operator` | The operator's ed25519 receipt key (32 bytes). |
| `recipient` | The clearing account to credit: this service's ed25519 key (32 bytes). |
| `onReceipt` | Called with every accepted receipt (`encoded` is the crate encoding) before the request is served. If it throws, the payment is refused and the receipt stays usable. |
| `store` | Optional atomic `Store` for per-payer watermarks. Share one across every instance that credits `recipient`. |

## Paying from an agent

```ts
import { Mppx } from 'mppx/client'
import { bajillion } from '@paradigmhack/mpp-bajillion/client'

const mppx = Mppx.create({
  methods: [bajillion({ operatorUrl: 'https://operator.example', secretKey: process.env.AGENT_KEY! })],
})
const response = await mppx.fetch('https://api.example.com/resource')
```

For each challenge the client extends its out-vector, signs the new endpoint, POSTs it to
`<operatorUrl>/accept-send`, checks the countersigned receipt exactly as the server will, and
retries the request with it. Pass a persistent `store` in production: losing the per-epoch
endpoint means the wallet can no longer sign the next sequence number.

## Layout

| Path | Contents |
|---|---|
| `src/codec.ts` | Crate byte encodings: `VectorAck`, `EntryReceipt`, `Opening`, `EpochContext` and the epoch anchor. |
| `src/ed25519.ts` | ZIP215 verification and strict-key checks, as `commonware-cryptography-curve25519` applies them. |
| `src/commitment.ts` | The out-entry vector commitment (leaf and root namespaces, BMT opening). |
| `src/receipt.ts` | `EntryReceipt::verify`, check for check. |
| `src/Methods.ts` | The shared `Method.from` definition. |
| `src/server`, `src/client` | `Method.toServer` and `Method.toClient` halves. |
| `test/vectors/entry-receipts.json` | Receipts the crate built over the fixture acks (`test/vectors/receiptgen`). |
| `test/vectors/ed25519-zip215.json` | The crate's Wycheproof verdicts and ZIP215 points. |

## Tests

```sh
npm install
npm test           # vitest
npm run typecheck
```

The tests check that every crate-built receipt over the fixture acknowledgments verifies and
re-encodes byte for byte, that each corrupted field is rejected with the crate's error, that all
151 Wycheproof vectors get the crate's ZIP215 verdicts, and that the method works end to end
through unmodified `mppx` servers and clients. That includes the one-line adoption next to `tempo`.

To regenerate the receipt vectors (needs the `contracts/lib/commonware` submodule and Rust 1.95):

```sh
cd test/vectors/receiptgen && cargo run --release > ../entry-receipts.json
```
