/**
 * PaymentBroker — phase 1 (x402 `exact` + MPP `charge` over Tempo).
 *
 * The broker mediates 402-with-payment-proof flows. These tests exercise:
 *   - The 402 challenge synthesis (both x402 and MPP headers)
 *   - Rail-intersection between request `accepts` and identity instruments
 *   - The no-instrument path (caller has no compatible rail at all)
 *   - The success path with a fake facilitator (both x402 and MPP receipts)
 *   - The session() not-implemented stub
 *   - instrumentsFor() pass-through
 */
import { describe, it, expect } from 'vitest'
import { PaymentBrokerImpl } from '../src/sdk/payment/broker-impl'
import type {
  FacilitatorClient,
  FacilitatorSettleRequest,
  FacilitatorSettleResponse,
  FacilitatorVerifyRequest,
  FacilitatorVerifyResponse,
} from '../src/sdk/payment/facilitator'
import type { Identity } from '../src/sdk/types'
import type { PaymentInstrument, PaymentRequired } from '../src/sdk/payment/types'

// ────────────────────────────────────────────────────────────────────────
// Test doubles
// ────────────────────────────────────────────────────────────────────────

class FakeFacilitator implements FacilitatorClient {
  verifyResult: FacilitatorVerifyResponse = { valid: true, payer: '0xabc' }
  settleResult: FacilitatorSettleResponse = {
    success: true,
    transaction: 'tx_123',
    network: 'eip155:8453',
    payer: '0xabc',
  }
  verifyCalls: FacilitatorVerifyRequest[] = []
  settleCalls: FacilitatorSettleRequest[] = []

  async verify(req: FacilitatorVerifyRequest): Promise<FacilitatorVerifyResponse> {
    this.verifyCalls.push(req)
    return this.verifyResult
  }
  async settle(req: FacilitatorSettleRequest): Promise<FacilitatorSettleResponse> {
    this.settleCalls.push(req)
    return this.settleResult
  }
}

const usdcOnBaseRails = [
  { protocol: 'x402' as const, method: 'exact' as const, network: 'eip155:8453', asset: 'USDC' },
  { protocol: 'mpp' as const, method: 'tempo' as const, network: 'eip155:8453', asset: 'USDC' },
]

const lightningOnlyRails = [
  { protocol: 'mpp' as const, method: 'lightning' as const, asset: 'BTC' },
]

function instrument(rails: PaymentInstrument['rails'], id = 'pi_1'): PaymentInstrument {
  return { id, rails }
}

function identity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'id-1',
    type: 'agent',
    name: 'test',
    verified: false,
    level: 1,
    claimStatus: 'unclaimed',
    paymentInstruments: [instrument(usdcOnBaseRails)],
    ...overrides,
  } as Identity
}

function makeBroker(facilitator: FacilitatorClient = new FakeFacilitator()) {
  return new PaymentBrokerImpl({
    facilitator,
    defaultPayTo: '0xmerchant',
    realm: 'id.org.ai',
    resourceUrl: 'https://api.example.com/tools/echo',
  })
}

function plainGet(url = 'https://api.example.com/tools/echo'): Request {
  return new Request(url, { method: 'POST' })
}

const bareCharge: PaymentRequired = { amount: '0.01' }

// base64 helpers (mirror what the rails module uses on the wire).
function b64(s: string) {
  const bytes = new TextEncoder().encode(s)
  let bin = ''
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!)
  return btoa(bin)
}
function b64url(s: string) {
  return b64(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function b64Decode(s: string): string {
  const bin = atob(s)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return new TextDecoder().decode(bytes)
}

// ────────────────────────────────────────────────────────────────────────
// 402 synthesis
// ────────────────────────────────────────────────────────────────────────

describe('PaymentBroker.settle — 402 challenge synthesis', () => {
  it('returns 402 with both WWW-Authenticate: Payment and PAYMENT-REQUIRED when no proof presented', async () => {
    const broker = makeBroker()
    const result = await broker.settle(plainGet(), identity(), bareCharge)
    expect(result.ok).toBe(false)
    if (result.ok) return

    expect(result.reason).toBe('no-payment')
    expect(result.response.status).toBe(402)

    const wwwAuth = result.response.headers.get('WWW-Authenticate')
    expect(wwwAuth).toBeTruthy()
    expect(wwwAuth!.startsWith('Payment ')).toBe(true)
    expect(wwwAuth).toContain('intent=charge')
    expect(wwwAuth).toContain('method=tempo')

    const paymentRequired = result.response.headers.get('PAYMENT-REQUIRED')
    expect(paymentRequired).toBeTruthy()
    const decoded = JSON.parse(b64Decode(paymentRequired!))
    expect(decoded.x402Version).toBe(2)
    expect(decoded.resource).toBe('https://api.example.com/tools/echo')
    expect(Array.isArray(decoded.accepts)).toBe(true)
    expect(decoded.accepts.length).toBeGreaterThan(0)
  })

  it('intersects identity instruments with request accepts — only includes rails the identity can satisfy', async () => {
    const broker = makeBroker()
    // Identity supports x402-exact only; request accepts both rails.
    const id = identity({
      paymentInstruments: [
        instrument([
          {
            protocol: 'x402',
            method: 'exact',
            network: 'eip155:8453',
            asset: 'USDC',
          },
        ]),
      ],
    })
    const required: PaymentRequired = {
      intent: 'charge',
      accepts: [
        {
          rail: { protocol: 'x402', method: 'exact', network: 'eip155:8453' },
          amount: '0.01',
          asset: 'USDC',
          payTo: '0xmerchant',
        },
        {
          rail: { protocol: 'mpp', method: 'tempo', network: 'eip155:8453' },
          amount: '0.01',
          asset: 'USDC',
          payTo: '0xmerchant',
        },
      ],
    }

    const result = await broker.settle(plainGet(), id, required)
    expect(result.ok).toBe(false)
    if (result.ok) return

    expect(result.reason).toBe('no-payment')
    const x402 = result.response.headers.get('PAYMENT-REQUIRED')!
    const decoded = JSON.parse(b64Decode(x402))
    // Only the x402-exact rail survives intersection.
    expect(decoded.accepts.length).toBe(1)
    expect(decoded.accepts[0].scheme).toBe('exact')

    // No MPP challenge at all because the only intersecting rail is x402.
    const wwwAuth = result.response.headers.get('WWW-Authenticate')
    if (wwwAuth) {
      // If a header is emitted at all it should never reference tempo.
      expect(wwwAuth).not.toContain('method=tempo')
    }
  })

  it('returns no-instrument when identity has zero compatible rails', async () => {
    const broker = makeBroker()
    const id = identity({
      paymentInstruments: [instrument(lightningOnlyRails, 'pi_ln')],
    })
    const result = await broker.settle(plainGet(), id, bareCharge)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('no-instrument')
    expect(result.response.status).toBe(402)
  })
})

// ────────────────────────────────────────────────────────────────────────
// Successful settlement
// ────────────────────────────────────────────────────────────────────────

describe('PaymentBroker.settle — proof + facilitator success', () => {
  it('settles via x402 PAYMENT-SIGNATURE and emits PAYMENT-RESPONSE on the receipt', async () => {
    const facilitator = new FakeFacilitator()
    facilitator.settleResult = {
      success: true,
      transaction: 'tx_x402',
      network: 'eip155:8453',
      payer: '0xpayer',
    }
    const broker = makeBroker(facilitator)

    const proof = {
      accepted: {
        scheme: 'exact',
        network: 'eip155:8453',
        amount: '0.01',
        asset: 'USDC',
        payTo: '0xmerchant',
      },
      payload: {
        signature: '0xsig',
        authorization: {
          from: '0xpayer',
          to: '0xmerchant',
          value: '10000',
          validAfter: 0,
          validBefore: 9_999_999_999,
          nonce: '0x' + '0'.repeat(64),
        },
      },
    }
    const req = new Request('https://api.example.com/tools/echo', {
      method: 'POST',
      headers: { 'PAYMENT-SIGNATURE': b64(JSON.stringify(proof)) },
    })

    const result = await broker.settle(req, identity(), bareCharge)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.txRef).toBe('tx_x402')
    expect(result.amount).toBe('0.01')
    expect(result.asset).toBe('USDC')
    expect(result.rail.protocol).toBe('x402')
    expect(result.rail.method).toBe('exact')
    const [name, value] = result.responseHeader
    expect(name).toBe('PAYMENT-RESPONSE')
    const decoded = JSON.parse(b64Decode(value))
    expect(decoded.success).toBe(true)
    expect(decoded.transaction).toBe('tx_x402')

    expect(facilitator.verifyCalls).toHaveLength(1)
    expect(facilitator.settleCalls).toHaveLength(1)
  })

  it('settles via MPP Authorization: Payment and emits Payment-Receipt on the receipt', async () => {
    const facilitator = new FakeFacilitator()
    facilitator.settleResult = {
      success: true,
      transaction: 'tx_mpp',
      network: 'eip155:8453',
      payer: '0xpayer',
    }
    const broker = makeBroker(facilitator)

    const proofPayload = b64url(
      JSON.stringify({
        voucher: { from: '0xpayer', to: '0xmerchant', value: '10000', expires: 9_999_999_999 },
        signature: '0xsig',
      }),
    )
    const auth = `Payment id="chg_1", realm="id.org.ai", method=tempo, intent=charge, proof="${proofPayload}"`
    const req = new Request('https://api.example.com/tools/echo', {
      method: 'POST',
      headers: { Authorization: auth },
    })

    const result = await broker.settle(req, identity(), bareCharge)
    expect(result.ok).toBe(true)
    if (!result.ok) return
    expect(result.txRef).toBe('tx_mpp')
    expect(result.rail.protocol).toBe('mpp')
    expect(result.rail.method).toBe('tempo')
    const [name, value] = result.responseHeader
    expect(name).toBe('Payment-Receipt')
    expect(typeof value).toBe('string')
    expect(value.length).toBeGreaterThan(0)
  })

  it('maps a failing facilitator verify to a 402 with reason=verify-failed', async () => {
    const facilitator = new FakeFacilitator()
    facilitator.verifyResult = { valid: false, reason: 'declined' }
    const broker = makeBroker(facilitator)

    const proof = { accepted: { scheme: 'exact' }, payload: { signature: '0xbad' } }
    const req = new Request('https://api.example.com/tools/echo', {
      method: 'POST',
      headers: { 'PAYMENT-SIGNATURE': b64(JSON.stringify(proof)) },
    })

    const result = await broker.settle(req, identity(), bareCharge)
    expect(result.ok).toBe(false)
    if (result.ok) return
    expect(result.reason).toBe('verify-failed')
    expect(result.response.status).toBe(402)
  })
})

// ────────────────────────────────────────────────────────────────────────
// instrumentsFor() and session()
// ────────────────────────────────────────────────────────────────────────

describe('PaymentBroker.instrumentsFor', () => {
  it('returns the identity-bound instruments verbatim', async () => {
    const broker = makeBroker()
    const id = identity()
    const result = await broker.instrumentsFor(id)
    expect(result).toEqual(id.paymentInstruments)
  })

  it('returns [] when identity has no instruments', async () => {
    const broker = makeBroker()
    const result = await broker.instrumentsFor(identity({ paymentInstruments: undefined }))
    expect(result).toEqual([])
  })
})

describe('PaymentBroker.session', () => {
  it('throws not-implemented (deferred to a later pass)', async () => {
    const broker = makeBroker()
    await expect(
      broker.session(identity(), {
        intent: 'session',
        budget: '1.00',
        ttlSeconds: 600,
        accepts: [],
      }),
    ).rejects.toThrow(/not yet implemented/i)
  })
})
