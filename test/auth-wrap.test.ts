/**
 * `wrap()` — composes AuthBroker.check() with a handler. Returns a denial
 * Response on failure, calls the handler with the resolved Identity on
 * success.
 */
import { describe, it, expect, vi } from 'vitest'
import { AuthBrokerImpl } from '../src/sdk/auth/broker-impl'
import { wrap, denialResponse, statusForDenial } from '../src/sdk/auth/wrap'
import type { Identity } from '../src/sdk/types'

const broker = new AuthBrokerImpl()

function identity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'id-1',
    type: 'agent',
    name: 'test',
    verified: false,
    level: 1,
    claimStatus: 'unclaimed',
    ...overrides,
  } as Identity
}

describe('wrap — success path', () => {
  it('calls the handler with the resolved Identity when the check passes', async () => {
    const handler = vi.fn(async (id: Identity) => new Response(`hello ${id.name}`, { status: 200 }))
    const guarded = wrap(broker, 1, handler)
    const id = identity({ level: 2, name: 'alice' })
    const res = await guarded(id, undefined)
    expect(handler).toHaveBeenCalledTimes(1)
    expect(handler.mock.calls[0]?.[0]).toBe(id)
    expect(res.status).toBe(200)
    expect(await res.text()).toBe('hello alice')
  })

  it('forwards the caller context to the handler unchanged', async () => {
    const handler = vi.fn(async (_id: Identity, ctx: { tag: string }) =>
      new Response(ctx.tag, { status: 200 }),
    )
    const guarded = wrap(broker, 0, handler)
    const res = await guarded(identity(), { tag: 'opaque-context' })
    expect(await res.text()).toBe('opaque-context')
  })
})

describe('wrap — denial paths', () => {
  it('returns 403 insufficient_level when level is below requirement', async () => {
    const handler = vi.fn(async () => new Response('reached', { status: 200 }))
    const guarded = wrap(broker, 2, handler)
    const res = await guarded(identity({ level: 1 }), undefined)
    expect(handler).not.toHaveBeenCalled()
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('insufficient_level')
  })

  it('returns 403 forbidden when a required scope is missing', async () => {
    const handler = vi.fn(async () => new Response('reached', { status: 200 }))
    const guarded = wrap(broker, { scopes: ['write'] }, handler)
    const res = await guarded(identity({ scopes: ['read'] }), undefined)
    expect(handler).not.toHaveBeenCalled()
    expect(res.status).toBe(403)
  })

  it('returns 403 access_denied when the identity is frozen, regardless of level', async () => {
    const handler = vi.fn(async () => new Response('reached', { status: 200 }))
    const guarded = wrap(broker, 1, handler)
    const res = await guarded(identity({ level: 3, frozen: true }), undefined)
    expect(handler).not.toHaveBeenCalled()
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('access_denied')
  })
})

describe('denialResponse / statusForDenial', () => {
  it('statusForDenial maps reasons to HTTP status', () => {
    expect(statusForDenial('unauthenticated')).toBe(401)
    expect(statusForDenial('rate-limited')).toBe(429)
    expect(statusForDenial('frozen')).toBe(403)
    expect(statusForDenial('insufficient-level')).toBe(403)
    expect(statusForDenial('missing-scope')).toBe(403)
    expect(statusForDenial('forbidden')).toBe(403)
  })

  it('denialResponse uses decision.response when present (pre-baked from gate())', async () => {
    const prebaked = new Response('pre-baked', { status: 401 })
    const res = denialResponse({
      ok: false,
      identity: null,
      reason: 'unauthenticated',
      response: prebaked,
    })
    expect(res).toBe(prebaked)
  })

  it('denialResponse synthesises a JSON body when no pre-baked response exists', async () => {
    const res = denialResponse({
      ok: false,
      identity: identity({ level: 0 }),
      reason: 'insufficient-level',
    })
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('insufficient_level')
    expect(typeof body.error_description).toBe('string')
  })
})
