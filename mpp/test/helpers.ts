import { readFileSync } from 'node:fs'
import { ed25519 } from '@noble/curves/ed25519.js'
import {
  type EpochContext,
  type OutEntry,
  Reader,
  type SendBody,
  compare,
  computeAnchor,
  concat,
  decodeEpochContext,
  encodeEpochContext,
  encodeOpening,
  encodeOutEntry,
  encodeVectorAck,
  equal,
  fromHex,
  readSendBody,
  sendMessage,
  toHex,
  u64,
  unionUnique,
  varint,
} from '../src/codec.js'
import { build } from '../src/commitment.js'
import { VECTOR_ACK_NAMESPACE, VECTOR_SEND_NAMESPACE } from '../src/receipt.js'

const FIXTURES = new URL('../../contracts/test/fixtures/', import.meta.url)

export const manifest = JSON.parse(readFileSync(new URL('manifest.json', FIXTURES), 'utf8'))

export function fixture(name: string): Uint8Array {
  return fromHex(readFileSync(new URL(`${name}.hex`, FIXTURES), 'utf8').trim())
}

/** Crate-built receipts over the fixture acknowledgments (test/vectors/receiptgen). */
export const crateReceipts: {
  ack: string
  payer: string
  recipient: string
  position: number
  cumulative: number
  count: number
  receipt: `0x${string}`
}[] = JSON.parse(readFileSync(new URL('./vectors/entry-receipts.json', import.meta.url), 'utf8')).receipts

export function crateReceipt(ack: string, recipient: string) {
  const found = crateReceipts.find((row) => row.ack === ack && row.recipient === recipient)
  if (!found) throw new Error(`no crate receipt for ${ack} -> ${recipient}`)
  return found
}

export const accountKey = (name: string): `0x${string}` =>
  manifest.scenario.accounts.find((account: { name: string }) => account.name === name).public_key

export const epochContextHex = toHex(fixture('epoch_context'))
export const operatorKey: `0x${string}` = manifest.scenario.operator
export const currency = '0x20c0000000000000000000000000000000000000'

/** The fixture epoch context re-registered under another operator key, with its anchor recomputed. */
export function contextFor(operator: Uint8Array): EpochContext {
  const context = decodeEpochContext(fixture('epoch_context'))
  const rekeyed = { ...context, payment: { ...context.payment, operator } }
  return { ...rekeyed, payment: { ...rekeyed.payment, anchor: computeAnchor(rekeyed) } }
}

export const randomSecret = () => ed25519.utils.randomSecretKey()

type Edge = { seq: bigint; debit: bigint; entries: OutEntry[] }

/**
 * A minimal operator for the accept-send HTTP binding, written against the crate's rules rather
 * than the client: it checks the payer signature, predecessor, sequence, debit and vector root,
 * countersigns, and opens each credited entry. Anything else gets a stale report.
 */
export function mockOperator(options: { requiredPredecessor?: (payer: Uint8Array) => Uint8Array; tamper?: boolean } = {}) {
  const secretKey = randomSecret()
  const key = ed25519.getPublicKey(secretKey)
  const context = contextFor(key)
  const edges = new Map<string, Edge>()
  const requests: Uint8Array[] = []

  function handle(bytes: Uint8Array): Uint8Array {
    requests.push(bytes)
    const reader = new Reader(bytes)
    const body: SendBody = readSendBody(reader)
    const predecessor = reader.take(32)
    const signature = reader.take(64)
    const deltas = Array.from({ length: reader.varint() }, () => ({ recipient: reader.strictKey(), amount: reader.u64() }))
    reader.end()

    const edge = edges.get(toHex(body.payer)) ?? { seq: 0n, debit: 0n, entries: [] }
    const required = options.requiredPredecessor?.(body.payer)
    const entries = edge.entries.map((entry) => ({ ...entry }))
    for (const delta of deltas) {
      const found = entries.find((entry) => equal(entry.recipient, delta.recipient))
      if (found) {
        found.cumulative += delta.amount
        found.count += 1n
      } else entries.push({ recipient: delta.recipient, cumulative: delta.amount, count: 1n })
    }
    entries.sort((left, right) => compare(left.recipient, right.recipient))
    const total = deltas.reduce((sum, delta) => sum + delta.amount, 0n)
    const tree = build(entries)
    const message = sendMessage(body, predecessor)
    const valid =
      equal(body.anchor, context.payment.anchor) &&
      body.epoch === context.payment.epoch &&
      ed25519.verify(signature, unionUnique(VECTOR_SEND_NAMESPACE, message), body.payer) &&
      (required === undefined || equal(predecessor, required)) &&
      body.seq === edge.seq + 1n &&
      body.cumulativeDebit === edge.debit + total &&
      equal(tree.root, body.sendRoot)
    if (!valid) {
      return concat(
        Uint8Array.of(1),
        context.payment.anchor,
        u64(context.payment.epoch),
        context.payment.operator,
        u64(body.epoch),
        u64(edge.debit),
        u64(edge.seq),
        varint(edge.entries.length),
        ...edge.entries.map(encodeOutEntry),
        required ?? predecessor,
      )
    }
    edges.set(toHex(body.payer), { seq: body.seq, debit: body.cumulativeDebit, entries })
    const operatorSignature = ed25519.sign(unionUnique(VECTOR_ACK_NAMESPACE, message), secretKey)
    if (options.tamper) operatorSignature[0]! ^= 1
    const opened = deltas.map((delta) => {
      const position = entries.findIndex((entry) => equal(entry.recipient, delta.recipient))
      return concat(encodeOutEntry(entries[position]!), encodeOpening(tree.opening(position)))
    })
    return concat(
      Uint8Array.of(0),
      u64(body.epoch),
      u64(body.seq),
      u64(total),
      encodeVectorAck({ body, predecessor, payerSignature: signature, operatorSignature }),
      varint(opened.length),
      ...opened,
    )
  }

  return {
    context,
    contextHex: toHex(encodeEpochContext(context)),
    key: toHex(key),
    requests,
    async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
      const request = new Request(input, init)
      if (request.method !== 'POST' || !request.url.endsWith('/accept-send')) return new Response('not found', { status: 404 })
      const response = handle(new Uint8Array(await request.arrayBuffer()))
      return new Response(response as BodyInit, { headers: { 'content-type': 'application/octet-stream' } })
    },
  }
}
