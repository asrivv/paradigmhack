import { Credential, Method } from 'mppx'
import {
  type EntryReceipt,
  type OutEntry,
  type SendBody,
  compare,
  decodeEpochContext,
  encodeEntryReceipt,
  encodeSendBody,
  equal,
  fromHex,
  sendMessage,
  toHex,
} from '../codec.js'
import { build, emptyRoot } from '../commitment.js'
import { isStrictKey, publicKey, sign } from '../ed25519.js'
import * as Methods from '../Methods.js'
import { VECTOR_SEND_NAMESPACE, verifyEntryReceipt } from '../receipt.js'
import { type AcceptSendResponse, acceptSend, encodeAcceptSendRequest } from './operator.js'

type MaybePromise<value> = value | Promise<value>

/** The payer's acknowledged endpoint in one epoch, in a JSON-safe form. */
export type VectorState = {
  anchor: string
  cumulativeDebit: string
  entries: { count: string; cumulative: string; recipient: string }[]
  /** Predecessor root every body of this epoch binds. */
  predecessor: string
  sendRoot: string
  seq: string
}

/** Durable per-epoch vector state. Payments from one wallet key must share one store. */
export type WalletStore = {
  get(epoch: bigint): MaybePromise<VectorState | undefined>
  put(epoch: bigint, state: VectorState): MaybePromise<void>
}

/** The operator refused the send because it does not extend the state the operator holds. */
export class StaleSendError extends Error {
  override readonly name = 'StaleSendError'
  constructor(
    message: string,
    readonly report: Extract<AcceptSendResponse, { type: 'stale' }>,
  ) {
    super(message)
  }
}

/**
 * Client half of the Bajillion charge method.
 *
 * For each challenge it extends the wallet's out-vector by `amount` to `recipient`, signs the
 * new endpoint, has the operator at `operatorUrl` countersign it, checks the returned receipt
 * as the server will, and sends that `EntryReceipt` as the credential.
 */
export function charge(parameters: charge.Parameters) {
  const secretKey = fromHex(parameters.secretKey, 32)
  const payer = publicKey(secretKey)
  const store = parameters.store ?? memoryStore()

  async function pay(challenge: Parameters<Method.CreateCredentialFn<typeof Methods.charge>>[0]['challenge']) {
    const { amount: amountText, methodDetails, recipient: recipientText } = challenge.request
    if (!methodDetails) throw new Error('challenge carries no epoch context')
    const context = decodeEpochContext(fromHex(methodDetails.epochContext)).payment
    const recipient = fromHex(recipientText, 32)
    const amount = BigInt(amountText)
    if (!isStrictKey(recipient)) throw new Error('challenge recipient is not a strict ed25519 key')
    if (equal(recipient, payer)) throw new Error('challenge asks the wallet to pay itself')

    const state = await store.get(context.epoch)
    if (state && !equal(fromHex(state.anchor), context.anchor)) throw new Error('wallet state belongs to another registration of this epoch')
    // Every body binds the root of the wallet's last vector in the preceding epoch, or the empty
    // root when it sent nothing there (payment.rs:270-276).
    const previous = state || context.epoch === 0n ? undefined : await store.get(context.epoch - 1n)
    let predecessorRoot = state ? fromHex(state.predecessor) : previous ? fromHex(previous.sendRoot) : emptyRoot()

    // A wallet's first send in an epoch may bind a predecessor it never saw close. One stale
    // reply that reports an empty endpoint in this exact epoch supplies the root to bind.
    for (let attempt = 0; ; attempt++) {
      const entries: OutEntry[] = (state?.entries ?? []).map((entry) => ({
        count: BigInt(entry.count),
        cumulative: BigInt(entry.cumulative),
        recipient: fromHex(entry.recipient),
      }))
      let position = entries.findIndex((entry) => equal(entry.recipient, recipient))
      if (position === -1) {
        entries.push({ count: 0n, cumulative: 0n, recipient })
        entries.sort((left, right) => compare(left.recipient, right.recipient))
        position = entries.findIndex((entry) => equal(entry.recipient, recipient))
      }
      const entry = entries[position]!
      entry.cumulative += amount
      entry.count += 1n
      const tree = build(entries)
      const body: SendBody = {
        anchor: context.anchor,
        cumulativeDebit: BigInt(state?.cumulativeDebit ?? 0) + amount,
        epoch: context.epoch,
        payer,
        sendRoot: tree.root,
        seq: BigInt(state?.seq ?? 0) + 1n,
      }
      const signature = sign(VECTOR_SEND_NAMESPACE, sendMessage(body, predecessorRoot), secretKey)
      const response = await acceptSend(
        parameters.operatorUrl,
        encodeAcceptSendRequest(body, predecessorRoot, signature, [{ amount, recipient }]),
        parameters.fetch,
      )

      if (response.type === 'stale') {
        const reportsEmptyEndpoint =
          equal(response.context.anchor, context.anchor) &&
          response.epoch === context.epoch &&
          response.seq === 0n &&
          response.cumulativeDebit === 0n &&
          response.entries.length === 0
        if (attempt === 0 && !state && reportsEmptyEndpoint && !equal(response.predecessor, predecessorRoot)) {
          predecessorRoot = response.predecessor
          continue
        }
        throw new StaleSendError(
          response.context.epoch > context.epoch
            ? `operator has moved to epoch ${response.context.epoch}; request a fresh challenge`
            : 'operator holds a payer endpoint this wallet does not',
          response,
        )
      }

      // Accept only a countersignature over exactly the endpoint signed above.
      const opened = response.entries[0]
      if (
        response.epoch !== context.epoch ||
        response.sequence !== body.seq ||
        response.total !== amount ||
        !equal(encodeSendBody(response.ack.body), encodeSendBody(body)) ||
        !equal(response.ack.predecessor, predecessorRoot) ||
        response.entries.length !== 1 ||
        !opened ||
        !equal(opened.recipient, recipient) ||
        opened.cumulative !== entry.cumulative ||
        opened.count !== entry.count
      )
        throw new Error('operator acknowledged a different payment')
      const receipt: EntryReceipt = { ack: response.ack, ...opened }
      verifyEntryReceipt(receipt, context)

      await store.put(context.epoch, {
        anchor: toHex(context.anchor),
        cumulativeDebit: body.cumulativeDebit.toString(),
        entries: entries.map((entry) => ({
          count: entry.count.toString(),
          cumulative: entry.cumulative.toString(),
          recipient: toHex(entry.recipient),
        })),
        predecessor: toHex(predecessorRoot),
        sendRoot: toHex(body.sendRoot),
        seq: body.seq.toString(),
      })
      return receipt
    }
  }

  return Method.toClient(Methods.charge, {
    async createCredential({ challenge }) {
      const receipt = await pay(challenge)
      return Credential.serialize({
        challenge,
        payload: { receipt: toHex(encodeEntryReceipt(receipt)), type: 'receipt' },
      })
    },
  })
}

export declare namespace charge {
  type Parameters = {
    /** Fetch used to reach the operator. Defaults to the global fetch. */
    fetch?: typeof globalThis.fetch | undefined
    /** Base URL of the operator's HTTP endpoint; sends are POSTed to `<operatorUrl>/accept-send`. */
    operatorUrl: string
    /** The wallet's ed25519 secret key (32-byte seed, 0x-hex). Its public key is the clearing account. */
    secretKey: string
    /** Where the wallet keeps its per-epoch endpoint. Defaults to process memory. */
    store?: WalletStore | undefined
  }
}

/** A {@link WalletStore} in process memory. State is lost on restart. */
export function memoryStore(): WalletStore {
  const states = new Map<bigint, VectorState>()
  return {
    get: (epoch) => states.get(epoch),
    put: (epoch, state) => {
      states.set(epoch, state)
    },
  }
}
