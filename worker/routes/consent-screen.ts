/**
 * Renders the consent screen (3a/3b/3c) for the provider's view model
 * (docs/product-update/spec/backend.md#b2): the signed-in person, their active
 * workspaces with one preselected, and the CSRF binding.
 *
 * CSRF (browser-direct requests): a fresh token is stored in the oauth DO
 * (single use, 30 minutes), set as the `__csrf` cookie and folded into the
 * form's `state` (`encodeStateWithCSRF`). POST /oauth/authorize checks the
 * double submit and hands the provider the client's original state back.
 * Service-binding (X-Issuer) and trusted-account requests render without it,
 * as before.
 */
import type { Context } from 'hono'
import type { Env, Variables } from '../types'
import type { ConsentViewModel } from '../../src/sdk/oauth/consent-view'
import { buildCSRFCookie, encodeStateWithCSRF, generateCSRFToken } from '../../src/sdk/csrf'
import { personAccount, personWorkspaces } from '../utils/person'
import { getStubForIdentity, readSessionOrgId } from '../middleware/tenant'
import { renderPage } from '../ui/render'
import { consentProps } from '../ui/consent-props'
import { Consent, consentTitle } from '../ui/screens/Consent'

type C = Context<{ Bindings: Env; Variables: Variables }>

export interface ConsentScreenOptions {
  /** Bind the form to a CSRF token (every browser-direct request). */
  csrf: boolean
}

export async function renderConsentScreen(c: C, vm: ConsentViewModel, opts: ConsentScreenOptions): Promise<Response> {
  const [person, orgs, sessionOrg] = await Promise.all([personAccount(c.env, vm.identityId), personWorkspaces(c.env, vm.identityId), readSessionOrgId(c.req.raw, c.env)])
  const isMember = (id: string | undefined) => !!id && orgs.some((o) => o.id === id)
  const selectedOrgId = [vm.orgHint, vm.rememberedOrgId, sessionOrg].find(isMember) ?? orgs[0]?.id

  // "Switch" signs in again and comes back to this same request (FEATURE_SESSIONS_V2 off).
  const here = new URL(c.req.url)
  const switchHref = `/login?prompt=login&continue=${encodeURIComponent(here.pathname + here.search)}`

  const fields = { ...vm.fields }
  let csrf = ''
  if (opts.csrf) {
    csrf = generateCSRFToken()
    await getStubForIdentity(c.env, 'oauth').oauthStorageOp({
      op: 'put',
      key: `csrf:${csrf}`,
      value: { token: csrf, createdAt: Date.now(), expiresAt: Date.now() + 30 * 60 * 1000 },
    })
    fields.state = encodeStateWithCSRF(csrf, vm.fields.state)
  }

  const props = consentProps(vm, { account: person, workspaces: orgs, selectedOrgId, switchHref, fields, csrf })
  const res = await renderPage(c, Consent(props), {
    title: consentTitle(props),
    scripts: ['copy.js', 'submit.js', 'logo.js'],
    // The POST answers with a redirect to the app: form-action must allow its origin.
    formActionOrigins: [vm.redirect.origin],
  })
  if (opts.csrf) res.headers.append('Set-Cookie', buildCSRFCookie(csrf, new URL(c.req.url).protocol === 'https:'))
  return res
}
