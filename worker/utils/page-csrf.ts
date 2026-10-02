/**
 * CSRF for the pages' own POSTs (device entry, the device decision, sign a
 * device out): a double submit like consent's. A fresh token is stored in the
 * oauth DO (30 minutes, single use) and set as the `__csrf` cookie; the page
 * sends it back as the `csrf` field (a form post) or the `X-CSRF-Token` header
 * (fetch-form). Both must match the cookie and the stored token.
 */
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import { buildCSRFCookie, extractCSRFFromCookie, generateCSRFToken } from '../../src/sdk/csrf'
import { getStubForIdentity } from '../middleware/tenant'

type C = Context<{ Bindings: Env; Variables: Variables }>

const TTL_MS = 30 * 60 * 1000

/** A fresh token for a page, and the Set-Cookie value that carries it. */
export async function issuePageCsrf(c: C): Promise<{ token: string; cookie: string }> {
  const token = generateCSRFToken()
  await getStubForIdentity(c.env, 'oauth').oauthStorageOp({
    op: 'put',
    key: `csrf:${token}`,
    value: { token, createdAt: Date.now(), expiresAt: Date.now() + TTL_MS },
  })
  return { token, cookie: buildCSRFCookie(token, new URL(c.req.url).protocol === 'https:') }
}

/**
 * Is `submitted` (the field or the header) this browser's live token? Spends
 * it when it is, so a page's token answers one POST.
 */
export async function checkPageCsrf(c: C, submitted: string | undefined): Promise<boolean> {
  const cookie = extractCSRFFromCookie(c.req.raw)
  if (!cookie || !submitted || cookie !== submitted) return false
  const stub = getStubForIdentity(c.env, 'oauth')
  const stored = (await stub.oauthStorageOp({ op: 'get', key: `csrf:${cookie}` })).value as { expiresAt?: number } | undefined
  if (!stored || (stored.expiresAt && Date.now() > stored.expiresAt)) return false
  await stub.oauthStorageOp({ op: 'delete', key: `csrf:${cookie}` })
  return true
}
