import { sha256 } from '@noble/hashes/sha2.js'
import { Errors, Method, Receipt, Store } from 'mppx'
import {
  DecodeError,
  type EntryReceipt,
  type EpochContext,
  decodeEntryReceipt,
  decodeEpochContext,
  equal,
  fromHex,
  toHex,
} from '../codec.js'
import { isStrictKey } from '../ed25519.js'
import * as Methods from '../Methods.js'
import { ReceiptError, verifyEntryReceipt } from '../receipt.js'

type MaybePromise<value> = value | Promise<value>

/** Highest accepted receipt on one payer-to-recipient edge in one epoch. */
type Watermark = { count: string; cumulative: string; seq: string }

/** What the `onReceipt` hook receives for every accepted payment. */
export type AcceptedReceipt = {
  /** The challenge the payment satisfied. */
  challenge: Methods.Credential['challenge']
  /** Credit this payment added on the edge: the receipt's cumulative minus the prior watermark. */
  credited: bigint
  /** The `EntryReceipt` exactly as the crate encodes it: the evidence to retain. */
  encoded: Uint8Array
  /** The epoch context the receipt verified under. */
  epochContext: EpochContext
  /** The decoded receipt. */
  receipt: EntryReceipt
}

/**
 * Server half of the Bajillion charge method.
 *
 * Challenges ask the payer to credit `recipient` by at least `amount` under the operator's live
 * epoch context. A credential carries the resulting `EntryReceipt`; it is accepted when it
 * verifies under that context and raises the payer's cumulative credit to `recipient` by at
 * least `amount` over the last receipt accepted on that edge.
 */
export function charge<const parameters extends charge.Parameters>(
  parameters: parameters,
): Method.Server<typeof Methods.charge, charge.Defaults<parameters>> {
  const operator = strictKey(parameters.operator, 'operator')
  const recipient = strictKey(parameters.recipient, 'recipient')
  const store = (parameters.store ?? Store.memory()) as Store.AtomicStore<Record<string, Watermark>>
  const resolveEpochContext =
    typeof parameters.epochContext === 'function' ? parameters.epochContext : () => parameters.epochContext as string

  async function check(credential: Methods.Credential) {
    const request = credential.challenge.request
    let epochContext: EpochContext
    try {
      epochContext = decodeEpochContext(fromHex(request.methodDetails?.epochContext ?? ''))
    } catch {
      throw new Errors.VerificationFailedError({ reason: 'challenge carries an invalid epoch context' })
    }
    if (!equal(epochContext.payment.operator, operator))
      throw new Errors.VerificationFailedError({ reason: 'challenge names another operator' })
    if (!equal(fromHex(request.recipient), recipient))
      throw new Errors.VerificationFailedError({ reason: 'challenge names another recipient' })

    let encoded: Uint8Array
    let receipt: EntryReceipt
    try {
      encoded = fromHex(credential.payload.receipt)
      receipt = decodeEntryReceipt(encoded)
    } catch (error) {
      throw new Errors.InvalidPayloadError({ reason: error instanceof DecodeError ? error.message : 'malformed receipt' })
    }
    try {
      verifyEntryReceipt(receipt, epochContext.payment)
    } catch (error) {
      if (error instanceof ReceiptError) throw new Errors.VerificationFailedError({ reason: error.code })
      throw error
    }
    if (!equal(receipt.recipient, recipient))
      throw new Errors.VerificationFailedError({ reason: 'receipt credits another recipient' })

    const key = `bajillion:edge:${toHex(epochContext.payment.anchor)}:${toHex(receipt.ack.body.payer)}:${toHex(recipient)}`
    const next: Watermark = {
      count: receipt.count.toString(),
      cumulative: receipt.cumulative.toString(),
      seq: receipt.ack.body.seq.toString(),
    }
    const amount = BigInt(request.amount)
    return { amount, encoded, epochContext, key, next, receipt, request }
  }

  /** Credit the receipt adds over `current`, or the reason it adds nothing usable. */
  function advance(current: Watermark | null, receipt: EntryReceipt, amount: bigint) {
    const cumulative = BigInt(current?.cumulative ?? 0)
    const count = BigInt(current?.count ?? 0)
    if (receipt.count <= count || receipt.cumulative <= cumulative) return { error: 'replayed' as const }
    const credited = receipt.cumulative - cumulative
    if (credited < amount) return { error: 'insufficient' as const, credited }
    return { credited }
  }

  function raise(result: ReturnType<typeof advance>, amount: bigint): never {
    if (result.error === 'replayed')
      throw new Errors.CredentialReplayedError({ reason: 'receipt does not advance the payer credit to this recipient' })
    throw new Errors.PaymentInsufficientError({ reason: `receipt adds ${result.credited} but the challenge requires ${amount}` })
  }

  const method = Method.toServer(Methods.charge, {
    canOffer: parameters.canOffer,
    onPaymentSuccess: parameters.onPaymentSuccess,
    defaults: {
      amount: parameters.amount,
      currency: parameters.currency,
      description: parameters.description,
      externalId: parameters.externalId,
      recipient: toHex(recipient),
    },
    async request({ request }) {
      return { ...request, epochContext: request.epochContext ?? (await resolveEpochContext()) }
    },
    async validate({ credential }) {
      const checked = await check(credential)
      const result = advance(await store.get(checked.key), checked.receipt, checked.amount)
      if (result.error) raise(result, checked.amount)
      return {
        challenge: credential.challenge,
        credential,
        details: { credited: result.credited.toString(), epoch: checked.epochContext.payment.epoch.toString() },
        intent: 'charge',
        method: 'bajillion',
        payer: toHex(checked.receipt.ack.body.payer),
        request: checked.request,
        source: credential.source,
      }
    },
    async broadcast({ credential }) {
      const checked = await check(credential)
      const { amount, encoded, epochContext, key, next, receipt } = checked
      // Raise the edge watermark atomically so concurrent copies of one receipt credit once.
      let previous: Watermark | null = null
      const result = await store.update(key, (current): Store.Change<Watermark, ReturnType<typeof advance>> => {
        previous = current
        const result = advance(current, receipt, amount)
        return result.error ? { op: 'noop', result } : { op: 'set', value: next, result }
      })
      if (result.error) raise(result, amount)

      try {
        await parameters.onReceipt?.({
          challenge: credential.challenge,
          credited: result.credited,
          encoded,
          epochContext,
          receipt,
        })
      } catch (error) {
        // Without retained evidence the payment is not safe to accept: release the watermark
        // (unless a later receipt already replaced it) so the payer can retry this credential.
        await store.update(key, (current): Store.Change<Watermark, void> =>
          current?.cumulative === next.cumulative && current.count === next.count
            ? previous
              ? { op: 'set', value: previous, result: undefined }
              : { op: 'delete', result: undefined }
            : { op: 'noop', result: undefined },
        )
        throw new Errors.InternalPaymentError({ cause: error })
      }

      return Receipt.from({
        cumulative: next.cumulative,
        epoch: epochContext.payment.epoch.toString(),
        externalId: credential.challenge.request.externalId,
        method: 'bajillion',
        payer: toHex(receipt.ack.body.payer),
        reference: toHex(sha256(encoded)),
        seq: next.seq,
        status: 'success',
        timestamp: new Date().toISOString(),
      })
    },
  })
  return method as never
}

export declare namespace charge {
  /** Request fields every route inherits; `amount` only when configured here. */
  type Defaults<parameters extends Parameters> = {
    currency: string
    epochContext: string
    recipient: string
  } & (parameters extends { amount: string } ? { amount: string } : {})

  type Parameters = Pick<Method.ComposableHooks<typeof Methods.charge>, 'canOffer' | 'onPaymentSuccess'> & {
    /** Default charge in base units; routes may override it. */
    amount?: string | undefined
    /** Settlement token of the Bajillion deployment, as a TIP-20 address. */
    currency: string
    description?: string | undefined
    /** Live `EpochContext` (264 bytes, 0x-hex) or a function resolving it per challenge. */
    epochContext: string | (() => MaybePromise<string>)
    externalId?: string | undefined
    /** Called with every accepted receipt before the payment is acknowledged. */
    onReceipt?: ((receipt: AcceptedReceipt) => MaybePromise<void>) | undefined
    /** The operator's ed25519 receipt key (32 bytes, 0x-hex). */
    operator: string
    /** The clearing account payments must credit (32 bytes, 0x-hex). */
    recipient: string
    /** Edge watermarks. Share one atomic store across every server crediting `recipient`. */
    store?: Store.AtomicStore | undefined
  }
}

function strictKey(value: string, name: string): Uint8Array {
  const key = fromHex(value, 32)
  if (!isStrictKey(key)) throw new Error(`${name} is not a strict ed25519 verifying key`)
  return key
}
