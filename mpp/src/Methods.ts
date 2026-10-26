import { Method, z } from 'mppx'

const U64_MAX = (1n << 64n) - 1n

/** Positive base-10 u64 with no sign, leading zero, exponent, or whitespace. */
const baseUnits = z
  .string()
  .check(z.regex(/^[1-9][0-9]*$/, 'amount must be a positive integer in base units'), z.refine((value) => BigInt(value) <= U64_MAX, 'amount exceeds u64'))

const bytes = (size: number) =>
  z.pipe(
    z.string().check(z.regex(new RegExp(`^0x[0-9a-fA-F]{${2 * size}}$`), `expected ${size} hex-encoded bytes`)),
    z.transform((value) => value.toLowerCase()),
  )

/**
 * Bajillion charge: one payment cleared through a Bajillion operator, proven by the
 * operator-countersigned `EntryReceipt` that credits the recipient.
 */
export const charge = Method.from({
  name: 'bajillion',
  intent: 'charge',
  schema: {
    credential: {
      payload: z.object({
        /** `EntryReceipt` in its crate encoding, 0x-prefixed hex. */
        receipt: z.string().check(z.regex(/^0x([0-9a-fA-F]{2})+$/, 'receipt must be hex bytes')),
        type: z.literal('receipt'),
      }),
    },
    request: z.pipe(
      z.object({
        amount: baseUnits,
        currency: z.string(),
        description: z.optional(z.string()),
        /**
         * `EpochContext` the operator acknowledges payments under (264 bytes). Optional only so
         * route definitions can omit it: the server's request hook fills it into every challenge.
         */
        epochContext: z.optional(bytes(264)),
        externalId: z.optional(z.string()),
        /** Clearing account credited by the payment: a strict ed25519 verifying key. */
        recipient: bytes(32),
      }),
      z.transform(({ epochContext, ...rest }) => ({
        ...rest,
        ...(epochContext === undefined ? {} : { methodDetails: { epochContext } }),
      })),
    ),
  },
})

/** Route-side request fields, before the schema moves `epochContext` into `methodDetails`. */
export type Input = z.input<typeof charge.schema.request>
/** A credential for this method with its payload and challenge request parsed. */
export type Credential = Method.VerifyContext<typeof charge>['credential']
