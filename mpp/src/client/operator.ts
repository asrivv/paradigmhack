// HTTP binding for the operator's accept-send call.
//
// The bodies are the reference terminal operator's (examples/terminal/src/operator/rpc.rs):
// the request is `AcceptSendRequest` (:177-204) and the response `AcceptSendResponse`
// (:548-616). That operator frames them over its own TCP RPC; here one HTTP POST carries one
// request body and a 2xx response carries one response body, both application/octet-stream.

import {
  DecodeError,
  type Opening,
  type OutEntry,
  type PaymentContext,
  Reader,
  type SendBody,
  type VectorAck,
  concat,
  encodeSendAuthorization,
  readOpening,
  readPaymentContext,
  readVectorAck,
  u64,
  varint,
} from '../codec.js'

/** `protocol::MAX_ENTRIES`: the most entries one send or report carries. */
const MAX_ENTRIES = 256

export type AcceptedEntry = OutEntry & { opening: Opening }

export type AcceptSendResponse =
  | {
      type: 'accepted'
      epoch: bigint
      sequence: bigint
      total: bigint
      ack: VectorAck
      entries: AcceptedEntry[]
    }
  | {
      type: 'stale'
      /** The operator's live payment context. */
      context: PaymentContext
      /** Epoch of the rejected send, which the endpoint below describes. */
      epoch: bigint
      cumulativeDebit: bigint
      seq: bigint
      entries: OutEntry[]
      /** The predecessor root every body of the live epoch must bind. */
      predecessor: Uint8Array
    }

export function encodeAcceptSendRequest(
  body: SendBody,
  predecessor: Uint8Array,
  payerSignature: Uint8Array,
  deltas: { recipient: Uint8Array; amount: bigint }[],
): Uint8Array {
  return concat(
    encodeSendAuthorization(body, predecessor, payerSignature),
    varint(deltas.length),
    ...deltas.map((delta) => concat(delta.recipient, u64(delta.amount))),
  )
}

function entryCount(reader: Reader, min: number): number {
  const count = reader.varint()
  if (count < min || count > MAX_ENTRIES) throw new DecodeError('entry count out of range')
  return count
}

export function decodeAcceptSendResponse(bytes: Uint8Array): AcceptSendResponse {
  const reader = new Reader(bytes)
  const tag = reader.u8()
  let response: AcceptSendResponse
  if (tag === 0) {
    const epoch = reader.u64()
    const sequence = reader.u64()
    const total = reader.u64()
    const ack = readVectorAck(reader)
    const entries = Array.from({ length: entryCount(reader, 1) }, () => ({
      recipient: reader.strictKey(),
      cumulative: reader.u64(),
      count: reader.u64(),
      opening: readOpening(reader),
    }))
    response = { type: 'accepted', epoch, sequence, total, ack, entries }
  } else if (tag === 1) {
    const context = readPaymentContext(reader)
    const epoch = reader.u64()
    const cumulativeDebit = reader.u64()
    const seq = reader.u64()
    const entries = Array.from({ length: entryCount(reader, 0) }, () => ({
      recipient: reader.strictKey(),
      cumulative: reader.u64(),
      count: reader.u64(),
    }))
    response = { type: 'stale', context, epoch, cumulativeDebit, seq, entries, predecessor: reader.take(32) }
  } else {
    throw new DecodeError(`unknown accept-send response tag ${tag}`)
  }
  reader.end()
  return response
}

export async function acceptSend(
  operatorUrl: string,
  request: Uint8Array,
  fetchFn: typeof globalThis.fetch = globalThis.fetch,
): Promise<AcceptSendResponse> {
  const response = await fetchFn(new URL('accept-send', operatorUrl.endsWith('/') ? operatorUrl : `${operatorUrl}/`), {
    body: request as BodyInit,
    headers: { 'content-type': 'application/octet-stream' },
    method: 'POST',
  })
  if (!response.ok) throw new Error(`operator rejected the send (${response.status}): ${(await response.text()).slice(0, 1024)}`)
  return decodeAcceptSendResponse(new Uint8Array(await response.arrayBuffer()))
}
