// `EntryReceipt::verify` (payment.rs:473-495) and `VectorAck::verify` (payment.rs:394-417),
// in the crate's order: context, payer signature, operator countersignature, entry
// feasibility, then the entry's opening under the signed send root.

import { type EntryReceipt, type PaymentContext, equal, sendMessage, utf8 } from './codec.js'
import { reconstruct } from './commitment.js'
import { verify } from './ed25519.js'

/** `VECTOR_SEND_SIGNATURE_NAMESPACE` (payment.rs:29). */
export const VECTOR_SEND_NAMESPACE = utf8('_COMMONWARE_CLEARING_VECTOR_SEND')
/** `VECTOR_ACK_SIGNATURE_NAMESPACE` (payment.rs:31). */
export const VECTOR_ACK_NAMESPACE = utf8('_COMMONWARE_CLEARING_VECTOR_ACK')

/** `AckError` variants an entry receipt can fail with (payment.rs `AckError`). */
export type ReceiptErrorCode =
  | 'WrongContext'
  | 'InvalidPayerSignature'
  | 'InvalidOperatorSignature'
  | 'InfeasibleEntry'
  | 'InvalidEntryOpening'

export class ReceiptError extends Error {
  override readonly name = 'ReceiptError'
  constructor(readonly code: ReceiptErrorCode) {
    super(`entry receipt rejected: ${code}`)
  }
}

export function verifyEntryReceipt(receipt: EntryReceipt, context: PaymentContext): void {
  const { body, predecessor } = receipt.ack
  if (!equal(body.anchor, context.anchor) || body.epoch !== context.epoch) throw new ReceiptError('WrongContext')
  const message = sendMessage(body, predecessor)
  if (!verify(VECTOR_SEND_NAMESPACE, message, receipt.ack.payerSignature, body.payer))
    throw new ReceiptError('InvalidPayerSignature')
  if (!verify(VECTOR_ACK_NAMESPACE, message, receipt.ack.operatorSignature, context.operator))
    throw new ReceiptError('InvalidOperatorSignature')
  if (receipt.cumulative === 0n || receipt.count === 0n || receipt.cumulative < receipt.count)
    throw new ReceiptError('InfeasibleEntry')
  const root = reconstruct(receipt.opening, receipt)
  if (root === undefined || !equal(root, body.sendRoot)) throw new ReceiptError('InvalidEntryOpening')
}
