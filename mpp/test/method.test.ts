import { ed25519 } from '@noble/curves/ed25519.js'
import { Challenge, Credential, Receipt } from 'mppx'
import { Mppx as ClientMppx } from 'mppx/client'
import { Mppx } from 'mppx/server'
import { describe, expect, test } from 'vitest'
import { bajillion as bajillionClient, StaleSendError } from '../src/client/index.js'
import { fromHex, toHex } from '../src/codec.js'
import { emptyRoot } from '../src/commitment.js'
import * as Methods from '../src/Methods.js'
import { type AcceptedReceipt, bajillion } from '../src/server/index.js'
import { accountKey, crateReceipt, currency, epochContextHex, mockOperator, operatorKey, randomSecret } from './helpers.js'

const secretKey = 'test-secret-key-with-at-least-32-bytes!!'
const url = 'https://api.example.com/resource'

/** A server for the fixture deployment whose recipient is account `d`. */
function fixtureServer(options: { amount?: string; onReceipt?: (receipt: AcceptedReceipt) => void } = {}) {
  return Mppx.create({
    methods: [
      bajillion({
        currency,
        epochContext: epochContextHex,
        onReceipt: options.onReceipt,
        operator: operatorKey,
        recipient: accountKey('d'),
      }),
    ],
    realm: 'api.example.com',
    secretKey,
  })
}

async function challengeFrom(server: ReturnType<typeof fixtureServer>, amount: string) {
  const result = await server.bajillion.charge({ amount })(new Request(url))
  expect(result.status).toBe(402)
  const response = result.challenge as Response
  return Challenge.fromResponse(response, { methods: [Methods.charge] })
}

async function pay(server: ReturnType<typeof fixtureServer>, amount: string, receipt: string) {
  const challenge = await challengeFrom(server, amount)
  const authorization = Credential.serialize({ challenge, payload: { receipt, type: 'receipt' } } as never)
  const result = await server.bajillion.charge({ amount })(new Request(url, { headers: { Authorization: authorization } }))
  // A refused credential comes back as a Response whose status the problem type decides.
  return result.status === 200 ? { ...result, status: 200 } : { status: (result.challenge as Response).status }
}

describe('server', () => {
  test('the 402 challenge offers bajillion with recipient, amount and epoch context', async () => {
    const challenge = await challengeFrom(fixtureServer(), '7')
    expect(challenge.method).toBe('bajillion')
    expect(challenge.intent).toBe('charge')
    expect(challenge.request).toEqual({
      amount: '7',
      currency,
      methodDetails: { epochContext: epochContextHex },
      recipient: accountKey('d'),
    })
  })

  test('a crate receipt pays the challenge and reaches onReceipt', async () => {
    const seen: AcceptedReceipt[] = []
    const server = fixtureServer({ onReceipt: (receipt) => void seen.push(receipt) })
    const { receipt } = crateReceipt('ack_c_seq0', 'd')
    const result = await pay(server, '7', receipt)
    expect(result.status).toBe(200)
    const response = (result as unknown as { withReceipt: (r: Response) => Response }).withReceipt(new Response('ok'))
    const issued = Receipt.fromResponse(response) as Receipt.Receipt & Record<string, string>
    expect(issued).toMatchObject({ method: 'bajillion', status: 'success', payer: accountKey('c'), cumulative: '7', epoch: '1' })
    expect(seen).toHaveLength(1)
    expect(toHex(seen[0]!.encoded)).toBe(receipt)
    expect(seen[0]!.credited).toBe(7n)
  })

  test('a later receipt on the same edge pays only its increase', async () => {
    const server = fixtureServer()
    // c -> d is 7 at seq0 and still 7 at seq1 (seq1 paid b), so seq1 adds nothing for d.
    expect((await pay(server, '7', crateReceipt('ack_c_seq0', 'd').receipt)).status).toBe(200)
    const replay = await pay(server, '1', crateReceipt('ack_c_seq1', 'd').receipt)
    expect(replay.status).toBe(403)
  })

  test('replaying one receipt is refused', async () => {
    const server = fixtureServer()
    const { receipt } = crateReceipt('ack_c_seq0', 'd')
    expect((await pay(server, '7', receipt)).status).toBe(200)
    expect((await pay(server, '7', receipt)).status).toBe(403)
  })

  test('a receipt worth less than the challenge is refused', async () => {
    expect((await pay(fixtureServer(), '8', crateReceipt('ack_c_seq0', 'd').receipt)).status).toBe(402)
  })

  test('a receipt crediting another recipient is refused', async () => {
    expect((await pay(fixtureServer(), '1', crateReceipt('ack_a_seq0', 'b').receipt)).status).toBe(402)
  })

  test('a corrupted receipt is refused with a fresh challenge', async () => {
    const bytes = fromHex(crateReceipt('ack_c_seq0', 'd').receipt)
    bytes[250]! ^= 1
    const result = await pay(fixtureServer(), '7', toHex(bytes))
    expect(result.status).toBe(402)
  })

  test('a failing onReceipt hook leaves the receipt usable', async () => {
    let fail = true
    const server = fixtureServer({
      onReceipt: () => {
        if (fail) throw new Error('storage down')
      },
    })
    const { receipt } = crateReceipt('ack_c_seq0', 'd')
    expect((await pay(server, '7', receipt)).status).not.toBe(200)
    fail = false
    expect((await pay(server, '7', receipt)).status).toBe(200)
  })
})

describe('client against an operator', () => {
  function setup(options: Parameters<typeof mockOperator>[0] = {}) {
    const operator = mockOperator(options)
    const payee = mockPayee(operator, randomSecret())
    const payerSecret = toHex(randomSecret())
    const client = ClientMppx.create({
      fetch: async (input, init) => {
        const request = new Request(input, init)
        const result = await payee.server.bajillion.charge({ amount: payee.amount })(request)
        if (result.status === 402) return result.challenge as Response
        return (result as { withReceipt: (r: Response) => Response }).withReceipt(new Response('paid'))
      },
      methods: [bajillionClient({ fetch: operator.fetch, operatorUrl: 'https://operator.example/', secretKey: payerSecret })],
      polyfill: false,
    })
    return { client, operator, payee }
  }

  function mockPayee(operator: ReturnType<typeof mockOperator>, recipientSecret: Uint8Array) {
    const received: AcceptedReceipt[] = []
    const recipient = toHex(ed25519PublicKey(recipientSecret))
    const server = Mppx.create({
      methods: [
        bajillion({
          currency,
          epochContext: operator.contextHex,
          onReceipt: (receipt) => void received.push(receipt),
          operator: operator.key,
          recipient,
        }),
      ],
      realm: 'api.example.com',
      secretKey,
    })
    return { amount: '3', received, recipient, server }
  }

  test('pays repeatedly from one deposit, one receipt per request', async () => {
    const { client, operator, payee } = setup()
    for (let i = 1; i <= 3; i++) {
      const response = await client.fetch(url)
      expect(response.status).toBe(200)
      expect(await response.text()).toBe('paid')
      expect(payee.received).toHaveLength(i)
      expect(payee.received[i - 1]!.receipt.cumulative).toBe(BigInt(3 * i))
      expect(payee.received[i - 1]!.receipt.ack.body.seq).toBe(BigInt(i))
      expect(toHex(payee.received[i - 1]!.receipt.ack.predecessor)).toBe(toHex(emptyRoot()))
    }
    expect(operator.requests).toHaveLength(3)
  })

  test('binds the predecessor the operator reports for a first send', async () => {
    const required = new Uint8Array(32).fill(7)
    const { client, operator, payee } = setup({ requiredPredecessor: () => required })
    const response = await client.fetch(url)
    expect(response.status).toBe(200)
    expect(operator.requests).toHaveLength(2)
    expect(toHex(payee.received[0]!.receipt.ack.predecessor)).toBe(toHex(required))
  })

  test('refuses an operator countersignature that does not verify', async () => {
    const { client, payee } = setup({ tamper: true })
    await expect(client.fetch(url)).rejects.toThrow()
    expect(payee.received).toHaveLength(0)
  })

  test('surfaces a stale operator', async () => {
    const operator = mockOperator()
    const other = mockOperator()
    const payee = mockPayee(other, randomSecret())
    const method = bajillionClient({ fetch: operator.fetch, operatorUrl: 'https://operator.example', secretKey: toHex(randomSecret()) })
    const challenge = await (async () => {
      const result = await payee.server.bajillion.charge({ amount: '1' })(new Request(url))
      return Challenge.fromResponse(result.challenge as Response, { methods: [Methods.charge] })
    })()
    await expect(method.createCredential({ challenge } as never)).rejects.toBeInstanceOf(StaleSendError)
  })
})

const ed25519PublicKey = (secret: Uint8Array) => ed25519.getPublicKey(secret)
