/**
 * requireScope / requireAllScopes — Hono middleware that gates routes on
 * scopes carried by the broker-resolved Identity. Tests invoke the
 * middleware directly with a fake Hono context.
 */
import { describe, it, expect, vi } from 'vitest'
import { requireScope, requireAllScopes } from '../worker/middleware/require-scope'
import type { Identity } from '../src/sdk/types'

function identity(overrides: Partial<Identity> = {}): Identity {
  return {
    id: 'id-1',
    type: 'agent',
    name: 'test',
    verified: false,
    level: 2,
    claimStatus: 'unclaimed',
    ...overrides,
  } as Identity
}

function fakeContext(id?: Identity) {
  const stored: Record<string, unknown> = id ? { identity: id } : {}
  let response: Response | undefined
  const c = {
    get: (k: string) => stored[k],
    set: (k: string, v: unknown) => {
      stored[k] = v
    },
    json: (body: unknown, status?: number) => {
      response = new Response(JSON.stringify(body), {
        status: status ?? 200,
        headers: { 'content-type': 'application/json' },
      })
      return response
    },
    req: {
      raw: new Request('https://test.example.com/x'),
    },
  }
  return { c, getResponse: () => response }
}

describe('requireScope (ANY-of)', () => {
  it('passes when the identity has one of the required scopes', async () => {
    const { c } = fakeContext(identity({ scopes: ['read', 'admin'] }))
    const next = vi.fn(async () => {})
    await requireScope('admin')(c, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('passes when ANY of multiple required scopes is present', async () => {
    const { c } = fakeContext(identity({ scopes: ['read'] }))
    const next = vi.fn(async () => {})
    await requireScope('admin', 'read', 'write')(c, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('returns 403 when none of the required scopes are present', async () => {
    const { c, getResponse } = fakeContext(identity({ scopes: ['read'] }))
    const next = vi.fn(async () => {})
    await requireScope('admin')(c, next)
    expect(next).not.toHaveBeenCalled()
    const res = getResponse()!
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect(body.error).toBe('forbidden')
    expect(typeof body.error_description).toBe('string')
    expect((body.error_description as string).toLowerCase()).toContain('admin')
  })

  it('returns 403 when identity has no scopes at all', async () => {
    const { c, getResponse } = fakeContext(identity({ scopes: undefined }))
    const next = vi.fn(async () => {})
    await requireScope('admin')(c, next)
    expect(next).not.toHaveBeenCalled()
    expect(getResponse()!.status).toBe(403)
  })

  it('returns 403 with frozen reason when identity is frozen, regardless of scopes', async () => {
    const { c, getResponse } = fakeContext(identity({ scopes: ['admin'], frozen: true }))
    const next = vi.fn(async () => {})
    await requireScope('admin')(c, next)
    expect(next).not.toHaveBeenCalled()
    const res = getResponse()!
    expect(res.status).toBe(403)
    const body = (await res.json()) as Record<string, unknown>
    expect((body.error_description as string).toLowerCase()).toContain('frozen')
  })

  it('returns 500 when authenticateRequest did not run (no identity context)', async () => {
    const { c, getResponse } = fakeContext()
    const next = vi.fn(async () => {})
    await requireScope('admin')(c, next)
    expect(next).not.toHaveBeenCalled()
    expect(getResponse()!.status).toBe(500)
  })

  it('throws at construction when called with no scopes', () => {
    expect(() => requireScope()).toThrow(/at least one scope/)
  })
})

describe('requireAllScopes (ALL-of)', () => {
  it('passes only when every required scope is present', async () => {
    const { c } = fakeContext(identity({ scopes: ['read', 'write', 'admin'] }))
    const next = vi.fn(async () => {})
    await requireAllScopes('read', 'write')(c, next)
    expect(next).toHaveBeenCalledTimes(1)
  })

  it('returns 403 when one of the required scopes is missing', async () => {
    const { c, getResponse } = fakeContext(identity({ scopes: ['read'] }))
    const next = vi.fn(async () => {})
    await requireAllScopes('read', 'write')(c, next)
    expect(next).not.toHaveBeenCalled()
    expect(getResponse()!.status).toBe(403)
  })

  it('throws at construction when called with no scopes', () => {
    expect(() => requireAllScopes()).toThrow(/at least one scope/)
  })
})
