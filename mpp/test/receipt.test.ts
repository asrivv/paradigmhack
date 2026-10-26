import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'vitest'
import {
  DecodeError,
  type EntryReceipt,
  concat,
  decodeEntryReceipt,
  decodeEpochContext,
  decodeVectorAck,
  encodeEntryReceipt,
  encodeOpening,
  fromHex,
  toHex,
  u32,
} from '../src/codec.js'
import { build, emptyRoot } from '../src/commitment.js'
import { isStrictKey, verifyRaw } from '../src/ed25519.js'
import { ReceiptError, verifyEntryReceipt } from '../src/receipt.js'
import { accountKey, crateReceipt, crateReceipts, fixture, manifest } from './helpers.js'

const context = decodeEpochContext(fixture('epoch_context')).payment

function rejection(bytes: Uint8Array, under = context): string {
  let receipt: EntryReceipt
  try {
    receipt = decodeEntryReceipt(bytes)
  } catch (error) {
    if (error instanceof DecodeError) return 'DecodeError'
    throw error
  }
  try {
    verifyEntryReceipt(receipt, under)
  } catch (error) {
    if (error instanceof ReceiptError) return error.code
    throw error
  }
  return 'accepted'
}

describe('fixture context', () => {
  test('the epoch context decodes with its anchor and operator', () => {
    expect(toHex(context.anchor)).toBe(manifest.hashes.epoch_anchor.digest)
    expect(toHex(context.operator)).toBe(manifest.scenario.operator)
    expect(context.epoch).toBe(BigInt(manifest.scenario.epoch))
  })

  test('the empty out-entry root is the predecessor every fixture ack signs', () => {
    for (const payment of manifest.scenario.payments) {
      expect(toHex(decodeVectorAck(fixture(payment.ack)).predecessor)).toBe(toHex(emptyRoot()))
    }
  })
})

describe('crate receipts', () => {
  test.each(crateReceipts)('$ack -> $recipient verifies and round-trips', (row) => {
    const bytes = fromHex(row.receipt)
    const receipt = decodeEntryReceipt(bytes)
    expect(toHex(encodeEntryReceipt(receipt))).toBe(row.receipt)
    expect(toHex(receipt.recipient)).toBe(accountKey(row.recipient))
    expect(toHex(receipt.ack.body.payer)).toBe(accountKey(row.payer))
    expect([receipt.cumulative, receipt.count]).toEqual([BigInt(row.cumulative), BigInt(row.count)])
    expect(rejection(bytes)).toBe('accepted')
  })

  test.each(crateReceipts)('$ack -> $recipient is rebuilt byte for byte from the fixture ack', (row) => {
    // Rebuild the payer's out-vector from the scenario, as the client does, and open the entry.
    const terminal = manifest.scenario.payments
      .filter((payment: { from: string; ack: string }) => payment.from === row.payer)
      .slice(0, Number(row.ack.at(-1)) + 1)
    const entries = new Map<string, { cumulative: bigint; count: bigint }>()
    for (const payment of terminal) {
      const entry = entries.get(payment.to) ?? { cumulative: 0n, count: 0n }
      entries.set(payment.to, { cumulative: entry.cumulative + BigInt(payment.amount), count: entry.count + 1n })
    }
    const sorted = [...entries]
      .map(([name, entry]) => ({ recipient: fromHex(accountKey(name)), ...entry }))
      .sort((left, right) => (toHex(left.recipient) < toHex(right.recipient) ? -1 : 1))
    const tree = build(sorted)
    const ack = decodeVectorAck(fixture(row.ack))
    expect(toHex(tree.root)).toBe(toHex(ack.body.sendRoot))
    const entry = sorted[row.position]!
    expect(toHex(entry.recipient)).toBe(accountKey(row.recipient))
    const rebuilt = encodeEntryReceipt({ ack, ...entry, opening: tree.opening(row.position) })
    expect(toHex(rebuilt)).toBe(row.receipt)
  })
})

describe('corrupted receipts are rejected', () => {
  // ack_c_seq1 credits b (position 0) and d (position 1) under one signed root, so the d
  // receipt carries one sibling. Offsets: body 0..120, predecessor ..152, payer signature
  // ..216, operator signature ..280, recipient ..312, cumulative ..320, count ..328,
  // position ..332, leaf count ..336, sibling count 336, sibling 337..369.
  const valid = fromHex(crateReceipt('ack_c_seq1', 'd').receipt)
  expect(valid.length).toBe(369)

  const L = (1n << 252n) + 27742317777372353535851937790883648493n
  const flip = (offset: number) => (bytes: Uint8Array) => {
    bytes[offset]! ^= 0x01
    return bytes
  }
  const put = (offset: number, value: Uint8Array) => (bytes: Uint8Array) => {
    bytes.set(value, offset)
    return bytes
  }
  const u64At = (offset: number, value: bigint) => {
    const out = new Uint8Array(8)
    new DataView(out.buffer).setBigUint64(0, value)
    return put(offset, out)
  }
  /** Replaces s with s + L: the same point equation, but a non-canonical scalar. */
  const malleate = (offset: number) => (bytes: Uint8Array) => {
    let s = 0n
    for (let i = 31; i >= 0; i--) s = (s << 8n) | BigInt(bytes[offset + 32 + i]!)
    s += L
    for (let i = 0; i < 32; i++, s >>= 8n) bytes[offset + 32 + i] = Number(s & 0xffn)
    return bytes
  }
  const identity = fromHex(`0x01${'00'.repeat(31)}`)

  const cases: [string, (bytes: Uint8Array) => Uint8Array, string][] = [
    ['anchor', flip(0), 'WrongContext'],
    ['epoch', u64At(32, 2n), 'WrongContext'],
    ['payer replaced by another account', put(40, fromHex(accountKey('a'))), 'InvalidPayerSignature'],
    ['payer replaced by a non-strict key', put(40, identity), 'DecodeError'],
    ['sequence', flip(79), 'InvalidPayerSignature'],
    ['cumulative debit', flip(87), 'InvalidPayerSignature'],
    ['send root', flip(88), 'InvalidPayerSignature'],
    ['predecessor', flip(120), 'InvalidPayerSignature'],
    ['payer signature R', flip(152), 'InvalidPayerSignature'],
    ['payer signature s', flip(184), 'InvalidPayerSignature'],
    ['payer signature with s + L', malleate(152), 'InvalidPayerSignature'],
    ['operator signature R', flip(216), 'InvalidOperatorSignature'],
    ['operator signature s', flip(248), 'InvalidOperatorSignature'],
    ['operator signature with s + L', malleate(216), 'InvalidOperatorSignature'],
    ['signatures swapped', (b) => concat(b.slice(0, 152), b.slice(216, 280), b.slice(152, 216), b.slice(280)), 'InvalidPayerSignature'],
    ['recipient replaced by the other credited account', put(280, fromHex(accountKey('b'))), 'InvalidEntryOpening'],
    ['recipient replaced by a non-strict key', put(280, identity), 'DecodeError'],
    ['cumulative raised', u64At(312, 8n), 'InvalidEntryOpening'],
    ['cumulative zero', u64At(312, 0n), 'InfeasibleEntry'],
    ['count raised', u64At(320, 2n), 'InvalidEntryOpening'],
    ['count zero', u64At(320, 0n), 'InfeasibleEntry'],
    ['count above cumulative', u64At(320, 8n), 'InfeasibleEntry'],
    ['position moved to the other entry', put(328, u32(0)), 'InvalidEntryOpening'],
    ['position outside the tree', put(328, u32(2)), 'DecodeError'],
    ['leaf count raised', put(332, u32(3)), 'InvalidEntryOpening'],
    ['leaf count above MAX_VECTOR_LENGTH', put(332, u32(2 ** 24 + 1)), 'DecodeError'],
    ['sibling', flip(337), 'InvalidEntryOpening'],
    ['sibling dropped', (b) => concat(b.slice(0, 336), Uint8Array.of(0)), 'InvalidEntryOpening'],
    ['sibling added', (b) => concat(b.slice(0, 336), Uint8Array.of(2), b.slice(337), b.slice(337)), 'InvalidEntryOpening'],
    ['sibling count above 32', (b) => concat(b.slice(0, 336), Uint8Array.of(33), ...Array(33).fill(b.slice(337))), 'DecodeError'],
    ['non-canonical sibling count', (b) => concat(b.slice(0, 336), Uint8Array.of(0x81, 0x00), b.slice(337)), 'DecodeError'],
    ['trailing byte', (b) => concat(b, Uint8Array.of(0)), 'DecodeError'],
    ['truncated', (b) => b.slice(0, -1), 'DecodeError'],
  ]

  test.each(cases)('%s', (_, mutate, expected) => {
    expect(rejection(mutate(valid.slice()))).toBe(expected)
  })

  test('another operator context', () => {
    expect(rejection(valid, { ...context, operator: fromHex(accountKey('a')) })).toBe('InvalidOperatorSignature')
  })

  test('a payer signature made under the operator namespace', () => {
    // challenge_higher_ack_debit_* are `tag || AckWitness || ...`; the witness is payer, seq, debit,
    // send root, predecessor, payer signature, operator signature (challenge.rs:121-143). The
    // wrong-role fixture's payer signature is over the ack namespace; the proven one is genuine.
    const fromWitness = (name: string) => {
      const witness = fixture(name).slice(1, 241)
      const ack = concat(context.anchor, fromHex('0x0000000000000001'), witness)
      // The opening is not under test here, so any well-formed one for entry 0 of 1 will do.
      return concat(ack, fromHex(accountKey('d')), fromHex('0x00000000000000070000000000000001'), encodeOpening({ position: 0, leafCount: 1, siblings: [] }))
    }
    expect(rejection(fromWitness('challenge_higher_ack_debit_wrong_payer_role'))).toBe('InvalidPayerSignature')
    expect(rejection(fromWitness('challenge_higher_ack_debit_proven'))).toBe('InvalidEntryOpening')
  })
})

describe('ed25519 matches the crate', () => {
  const vectors = JSON.parse(readFileSync(new URL('./vectors/ed25519-zip215.json', import.meta.url), 'utf8'))

  test('Wycheproof vectors get the crate ZIP215 verdicts', () => {
    const mismatches = vectors.wycheproof.filter(
      (vector: { publicKey: string; message: string; signature: string; validZip215: boolean }) =>
        verifyRaw(fromHex(vector.signature), fromHex(vector.message), fromHex(vector.publicKey)) !== vector.validZip215,
    )
    expect(vectors.wycheproof.length).toBe(151)
    expect(mismatches).toEqual([])
  })

  test('non-canonical and small-order A and R verify with s = 0, as ZIP215 requires', () => {
    const points: Uint8Array[] = vectors.zip215Points.map((point: string) => fromHex(point))
    for (const a of points)
      for (const r of points) expect(verifyRaw(concat(r, new Uint8Array(32)), new TextEncoder().encode('Zcash'), a)).toBe(true)
  })

  test('strict keys exclude every ZIP215 point and admit the fixture accounts', () => {
    for (const point of vectors.zip215Points) expect(isStrictKey(fromHex(point))).toBe(false)
    for (const name of ['a', 'b', 'c', 'd']) expect(isStrictKey(fromHex(accountKey(name)))).toBe(true)
    expect(isStrictKey(fromHex(manifest.scenario.operator))).toBe(true)
  })
})
