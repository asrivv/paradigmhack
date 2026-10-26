// Byte encodings of the `commonware-clearing` types this method carries, at
// commonwarexyz/monorepo dd6d60cb44fb3dc05cee1efa06d957ce30df1340 with D = SHA-256 and
// P = curve25519 StrictVerifyingKey. Paths below are relative to clearing/src/bajillion/.
//
// Integers are fixed-width big-endian; `usize` lengths are canonical LEB128 varints of a u32.
// Decoders accept exactly one encoding per value and reject trailing bytes, as `Decode` does.

import { sha256 } from '@noble/hashes/sha2.js'
import { isStrictKey } from './ed25519.js'

export const DIGEST_SIZE = 32
export const KEY_SIZE = 32
export const SIGNATURE_SIZE = 64

/** `VectorSendBody`: anchor, epoch, payer, seq, cumulative debit, send root (payment.rs:107-114). */
export const SEND_BODY_SIZE = DIGEST_SIZE + 8 + KEY_SIZE + 8 + 8 + DIGEST_SIZE
/** Every payer and operator signature covers the body followed by the predecessor root. */
export const SEND_MESSAGE_SIZE = SEND_BODY_SIZE + DIGEST_SIZE
/** `VectorAck`: message, payer signature, operator signature (payment.rs:428-433). */
export const VECTOR_ACK_SIZE = SEND_MESSAGE_SIZE + 2 * SIGNATURE_SIZE
/** `EpochContext` (transition.rs:690-704). */
export const EPOCH_CONTEXT_SIZE = 264

/** `bmt::Proof` decodes at most `max_items * MAX_LEVELS` siblings; an `Opening` proves one item. */
export const MAX_OPENING_SIBLINGS = 32
/** `commitment::MAX_VECTOR_LENGTH`. */
export const MAX_VECTOR_LENGTH = 1 << 24

const U64_MAX = (1n << 64n) - 1n

export class DecodeError extends Error {
  override readonly name = 'DecodeError'
}

export type PaymentContext = {
  anchor: Uint8Array
  epoch: bigint
  operator: Uint8Array
}

export type EpochContext = {
  payment: PaymentContext
  deployment: Uint8Array
  depositRoot: Uint8Array
  withdrawalRoot: Uint8Array
  limits: Uint8Array
  committee: Uint8Array
}

export type SendBody = {
  anchor: Uint8Array
  epoch: bigint
  payer: Uint8Array
  seq: bigint
  cumulativeDebit: bigint
  sendRoot: Uint8Array
}

export type VectorAck = {
  body: SendBody
  predecessor: Uint8Array
  payerSignature: Uint8Array
  operatorSignature: Uint8Array
}

/** `commitment::Opening`: one position and its BMT authentication path (commitment.rs:637-703). */
export type Opening = {
  position: number
  leafCount: number
  siblings: Uint8Array[]
}

export type OutEntry = {
  recipient: Uint8Array
  cumulative: bigint
  count: bigint
}

/** `payment::EntryReceipt` (payment.rs:460-525). */
export type EntryReceipt = OutEntry & {
  ack: VectorAck
  opening: Opening
}

// ---------------------------------------------------------------------------------------------
// Primitives
// ---------------------------------------------------------------------------------------------

export function concat(...parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0))
  let offset = 0
  for (const part of parts) {
    out.set(part, offset)
    offset += part.length
  }
  return out
}

export function equal(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false
  let diff = 0
  for (let i = 0; i < left.length; i++) diff |= left[i]! ^ right[i]!
  return diff === 0
}

export function compare(left: Uint8Array, right: Uint8Array): number {
  const length = Math.min(left.length, right.length)
  for (let i = 0; i < length; i++) if (left[i] !== right[i]) return left[i]! - right[i]!
  return left.length - right.length
}

export function toHex(bytes: Uint8Array): `0x${string}` {
  let out = '0x'
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0')
  return out as `0x${string}`
}

/** Parses `0x`-prefixed hex, optionally requiring an exact byte length. */
export function fromHex(value: string, size?: number): Uint8Array {
  if (!/^0x([0-9a-fA-F]{2})*$/.test(value)) throw new DecodeError('expected 0x-prefixed hex bytes')
  const bytes = new Uint8Array((value.length - 2) / 2)
  for (let i = 0; i < bytes.length; i++) bytes[i] = Number.parseInt(value.slice(2 + 2 * i, 4 + 2 * i), 16)
  if (size !== undefined && bytes.length !== size) throw new DecodeError(`expected ${size} bytes, got ${bytes.length}`)
  return bytes
}

export function u32(value: number): Uint8Array {
  const out = new Uint8Array(4)
  new DataView(out.buffer).setUint32(0, value)
  return out
}

export function u64(value: bigint): Uint8Array {
  if (value < 0n || value > U64_MAX) throw new RangeError('u64 out of range')
  const out = new Uint8Array(8)
  new DataView(out.buffer).setBigUint64(0, value)
  return out
}

export function varint(value: number): Uint8Array {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) throw new RangeError('varint out of range')
  const out: number[] = []
  do {
    let byte = value & 0x7f
    value = Math.floor(value / 128)
    if (value > 0) byte |= 0x80
    out.push(byte)
  } while (value > 0)
  return Uint8Array.from(out)
}

/** `union_unique`: `varint(namespace.len()) || namespace || message` (utils/src/lib.rs:183-192). */
export function unionUnique(namespace: Uint8Array, message: Uint8Array): Uint8Array {
  return concat(varint(namespace.length), namespace, message)
}

export const utf8 = (value: string): Uint8Array => new TextEncoder().encode(value)

export class Reader {
  private offset = 0
  constructor(private readonly bytes: Uint8Array) {}

  take(size: number): Uint8Array {
    if (this.bytes.length - this.offset < size) throw new DecodeError('unexpected end of buffer')
    const out = this.bytes.slice(this.offset, this.offset + size)
    this.offset += size
    return out
  }

  u32(): number {
    return new DataView(this.take(4).buffer).getUint32(0)
  }

  u64(): bigint {
    return new DataView(this.take(8).buffer).getBigUint64(0)
  }

  /** Canonical LEB128 u32, as `commonware_codec::varint` decodes it (codec/src/varint.rs:117-150). */
  varint(): number {
    let value = 0
    for (let index = 0; index < 5; index++) {
      const byte = this.take(1)[0]!
      if (index > 0 && byte === 0) throw new DecodeError('non-canonical varint')
      if (index === 4 && byte > 0x0f) throw new DecodeError('varint overflows u32')
      value += (byte & 0x7f) * 2 ** (7 * index)
      if ((byte & 0x80) === 0) return value
    }
    throw new DecodeError('varint overflows u32')
  }

  u8(): number {
    return this.take(1)[0]!
  }

  /** `StrictVerifyingKey::read` rejects non-canonical, identity and torsion points (signing.rs:457-470). */
  strictKey(): Uint8Array {
    const key = this.take(KEY_SIZE)
    if (!isStrictKey(key)) throw new DecodeError('public key is not a canonical non-identity prime-order point')
    return key
  }

  end(): void {
    if (this.offset !== this.bytes.length) throw new DecodeError('trailing bytes')
  }
}

// ---------------------------------------------------------------------------------------------
// Clearing types
// ---------------------------------------------------------------------------------------------

export function encodeSendBody(body: SendBody): Uint8Array {
  return concat(body.anchor, u64(body.epoch), body.payer, u64(body.seq), u64(body.cumulativeDebit), body.sendRoot)
}

/** The message both signatures cover: `body || predecessor` (payment.rs:188-196). */
export function sendMessage(body: SendBody, predecessor: Uint8Array): Uint8Array {
  return concat(encodeSendBody(body), predecessor)
}

export function readSendBody(reader: Reader): SendBody {
  return {
    anchor: reader.take(DIGEST_SIZE),
    epoch: reader.u64(),
    payer: reader.strictKey(),
    seq: reader.u64(),
    cumulativeDebit: reader.u64(),
    sendRoot: reader.take(DIGEST_SIZE),
  }
}

export function encodeVectorAck(ack: VectorAck): Uint8Array {
  return concat(sendMessage(ack.body, ack.predecessor), ack.payerSignature, ack.operatorSignature)
}

export function readVectorAck(reader: Reader): VectorAck {
  return {
    body: readSendBody(reader),
    predecessor: reader.take(DIGEST_SIZE),
    payerSignature: reader.take(SIGNATURE_SIZE),
    operatorSignature: reader.take(SIGNATURE_SIZE),
  }
}

export function decodeVectorAck(bytes: Uint8Array): VectorAck {
  const reader = new Reader(bytes)
  const ack = readVectorAck(reader)
  reader.end()
  return ack
}

/** `SendAuthorization`: body, predecessor, payer signature (payment.rs:331-337). */
export function encodeSendAuthorization(body: SendBody, predecessor: Uint8Array, payerSignature: Uint8Array) {
  return concat(sendMessage(body, predecessor), payerSignature)
}

export function encodeOutEntry(entry: OutEntry): Uint8Array {
  return concat(entry.recipient, u64(entry.cumulative), u64(entry.count))
}

export function encodeOpening(opening: Opening): Uint8Array {
  return concat(u32(opening.position), u32(opening.leafCount), varint(opening.siblings.length), ...opening.siblings)
}

export function readOpening(reader: Reader): Opening {
  const position = reader.u32()
  const leafCount = reader.u32()
  const siblingCount = reader.varint()
  if (siblingCount > MAX_OPENING_SIBLINGS) throw new DecodeError('opening has too many siblings')
  const siblings = Array.from({ length: siblingCount }, () => reader.take(DIGEST_SIZE))
  // `Opening::validate_shape` (commitment.rs:645-651).
  if (leafCount > MAX_VECTOR_LENGTH || position >= leafCount) throw new DecodeError('opening position or leaf count is invalid')
  return { position, leafCount, siblings }
}

export function encodeEntryReceipt(receipt: EntryReceipt): Uint8Array {
  return concat(encodeVectorAck(receipt.ack), encodeOutEntry(receipt), encodeOpening(receipt.opening))
}

export function decodeEntryReceipt(bytes: Uint8Array): EntryReceipt {
  const reader = new Reader(bytes)
  const receipt: EntryReceipt = {
    ack: readVectorAck(reader),
    recipient: reader.strictKey(),
    cumulative: reader.u64(),
    count: reader.u64(),
    opening: readOpening(reader),
  }
  reader.end()
  return receipt
}

export function readPaymentContext(reader: Reader): PaymentContext {
  return { anchor: reader.take(DIGEST_SIZE), epoch: reader.u64(), operator: reader.strictKey() }
}

export function encodePaymentContext(context: PaymentContext): Uint8Array {
  return concat(context.anchor, u64(context.epoch), context.operator)
}

export function encodeEpochContext(context: EpochContext): Uint8Array {
  return concat(
    encodePaymentContext(context.payment),
    context.deployment,
    context.depositRoot,
    context.withdrawalRoot,
    context.limits,
    context.committee,
  )
}

const EPOCH_ANCHOR_NAMESPACE = utf8('_COMMONWARE_CLEARING_EPOCH_ANCHOR')

/** `EpochContext::compute_anchor` (transition.rs:533-545). */
export function computeAnchor(context: EpochContext): Uint8Array {
  return sha256(
    concat(
      EPOCH_ANCHOR_NAMESPACE,
      context.deployment,
      context.depositRoot,
      context.withdrawalRoot,
      u64(context.payment.epoch),
      context.payment.operator,
      context.limits,
      context.committee,
    ),
  )
}

/** Decodes an `EpochContext` and requires `verify_anchor` to hold (transition.rs:547-551). */
export function decodeEpochContext(bytes: Uint8Array): EpochContext {
  const reader = new Reader(bytes)
  const context: EpochContext = {
    payment: readPaymentContext(reader),
    deployment: reader.take(DIGEST_SIZE),
    depositRoot: reader.take(DIGEST_SIZE),
    withdrawalRoot: reader.take(DIGEST_SIZE),
    limits: reader.take(64),
    committee: reader.take(DIGEST_SIZE),
  }
  reader.end()
  if (!equal(computeAnchor(context), context.payment.anchor)) throw new DecodeError('epoch anchor does not bind the context')
  return context
}
