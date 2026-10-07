/**
 * CSRF for the pages' own POSTs (device entry, the device decision, sign a
 * device out): a synchronizer token. Each page render stores a fresh token in
 * the oauth DO bound to the signed-in identity (30 minutes); the page sends it
 * back as the `csrf` field (a form post) or the `X-CSRF-Token` header
 * (fetch-form), and it is spent atomically (`takeOnce`) when it matches the
 * identity making the POST.
 *
 * Bound to the identity, so a token minted on someone else's page is useless
 * here even if a sibling host could plant cookies (phase 6 review S1); spent
 * in one DO call, so parallel posts can't all use it (S2); and no shared
 * cookie, so a second tab doesn't break the first.
 */
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import { generateCSRFToken } from '../../src/sdk/csrf'
import { getStubForIdentity } from '../middleware/tenant'

type C = Context<{ Bindings: Env; Variables: Variables }>

const TTL_MS = 30 * 60 * 1000

interface PageCsrfRecord {
  identityId: string
  expiresAt: number
}

/** A fresh token for a page rendered for `identityId`. */
export async function issuePageCsrf(c: C, identityId: string): Promise<string> {
  const token = generateCSRFToken()
  await getStubForIdentity(c.env, 'oauth').oauthStorageOp({
    op: 'put',
    key: `page-csrf:${token}`,
    value: { identityId, expiresAt: Date.now() + TTL_MS } satisfies PageCsrfRecord,
    options: { expirationTtl: TTL_MS / 1000 },
  })
  return token
}

/** Is `submitted` a live token minted for `identityId`? Spends it either way once looked up. */
export async function checkPageCsrf(c: C, submitted: string | undefined, identityId: string): Promise<boolean> {
  if (!submitted || !/^[A-Za-z0-9_-]{16,128}$/.test(submitted)) return false
  const { value } = await getStubForIdentity(c.env, 'oauth').takeOnce({ key: `page-csrf:${submitted}` })
  const rec = value as PageCsrfRecord | undefined
  return !!rec && rec.identityId === identityId && Date.now() <= rec.expiresAt
}
