import { Challenge } from 'mppx'
import { Mppx, tempo } from 'mppx/server'
import { expect, test } from 'vitest'
import { bajillion } from '../src/server/index.js'
import { accountKey, currency, epochContextHex, operatorKey } from './helpers.js'

test('an existing tempo server offers bajillion after adding one method', async () => {
  const mppx = Mppx.create({
    methods: [
      tempo({ recipient: '0x742d35Cc6634c0532925a3b844bC9e7595F8fE00', testnet: true }),
      bajillion({ currency, epochContext: epochContextHex, operator: operatorKey, recipient: accountKey('d') }),
    ],
    realm: 'api.example.com',
    secretKey: 'test-secret-key-with-at-least-32-bytes!!',
  })
  const result = await mppx.compose(
    [mppx.tempo.charge, { amount: '0.01' }],
    [mppx.bajillion.charge, { amount: '10000' }],
  )(new Request('https://api.example.com/resource'))
  expect(result.status).toBe(402)
  const offers = Challenge.fromResponseList(result.challenge as Response)
  // The tempo offers are whatever tempo emits on its own; bajillion adds exactly one.
  expect(offers.filter((offer) => offer.method === 'tempo').length).toBeGreaterThan(0)
  const added = offers.filter((offer) => offer.method === 'bajillion')
  expect(added).toHaveLength(1)
  expect(added[0]!.request).toMatchObject({ amount: '10000', recipient: accountKey('d') })
})
