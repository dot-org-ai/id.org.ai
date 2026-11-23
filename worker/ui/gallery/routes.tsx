/**
 * Design gallery: GET /__design (index), GET /__design/:slug?state=<name>, and
 * GET /__design/agent-setup (the agent setup screens by ID).
 *
 * Dev only. It answers only when env.DESIGN_GALLERY === '1' (worker/.dev.vars);
 * that is never set in wrangler.jsonc, so in production every /__design path
 * falls through to the normal 404. Pages render frozen (<html data-frozen>), so
 * nothing ticks, polls, redirects or autofocuses, and the visual diff
 * (docs/product-update/tools/visual-diff.mjs) compares them against the mocks.
 */
import { Hono } from 'hono'
import type { JSX } from 'hono/jsx/jsx-runtime'
import manifest from '../../../docs/product-update/mocks/manifest.json'
import { Card, Page } from '../components'
import { EMAIL_PREVIEW_CSP, renderPage, securityHeaders } from '../render'
import { AGENT_SCREENS, AgentSetupIndex, fixtureSlug } from './agent-setup-index'
import { ComponentSheet } from './components-sheet'
import type { Env, Variables } from '../../types'
import { AgentCard } from '../screens/agent-setup/AgentCard'
import { fixtures } from './fixtures'
import { paymentProps } from './fixtures/payments'
import type { BoundFixture, Variant } from './types'

type ManifestScreen = { id: string; slug: string; title: string; kind: string; states: { name: string }[] }
const SCREENS = (manifest as { screens: ManifestScreen[] }).screens

export const galleryRoutes = new Hono<{ Bindings: Env; Variables: Variables }>()

/** Without the flag every /__design path falls through to the app's ordinary 404. */
const enabled = (env: Env) => env.DESIGN_GALLERY === '1'

function Index(): JSX.Element {
  const listed = new Set(SCREENS.map((s) => s.slug))
  const extras = Object.keys(fixtures).filter((slug) => !listed.has(slug))
  const row = (slug: string, label: string, f: BoundFixture | undefined, states: string[]) => (
    <li class="id-gallery__row">
      {f ? <a href={`/__design/${slug}`}>{label}</a> : <span class="id-gallery__missing">{label}</span>}
      {states.map((st) =>
        f && (f.states[st] || f.derived[st]) ? (
          <a href={`/__design/${slug}?state=${st}`}>{st}</a>
        ) : (
          <span class="id-gallery__missing">{st}</span>
        ),
      )}
    </li>
  )
  return (
    <Page>
      <Card>
        <h1 class="id-gallery__title">Design gallery</h1>
        <a href="/__design/components">Component sheet</a>
        <a href="/__design/agent-setup">Agent setup, payments and connect: every screen by ID</a>
        <ul class="id-gallery">
          {SCREENS.map((s) => {
            const f = fixtures[s.slug]
            const states = [...s.states.map((x) => x.name), ...Object.keys(f?.derived ?? {})]
            return row(s.slug, s.title, f, states)
          })}
          {extras.map((slug) => row(slug, slug, fixtures[slug], Object.keys(fixtures[slug]?.derived ?? {})))}
        </ul>
      </Card>
    </Page>
  )
}

galleryRoutes.get('/__design', async (c, next) => {
  if (!enabled(c.env)) return next()
  return renderPage(c, <Index />, { title: 'Design gallery · id.org.ai', styles: ['gallery.css'] })
})

galleryRoutes.get('/__design/components', async (c, next) => {
  if (!enabled(c.env)) return next()
  return renderPage(c, <ComponentSheet />, { title: 'Components · id.org.ai', styles: ['gallery.css'], scripts: ['copy.js', 'code-input.js', 'logo.js', 'countdown.js', 'disclose.js', 'follow.js', 'terms.js', 'ago.js', 'stripe-fields.js'], frozen: true })
})

galleryRoutes.get('/__design/agent-setup', async (c, next) => {
  if (!enabled(c.env)) return next()
  return renderPage(c, <AgentSetupIndex fixtures={fixtures} />, { title: 'Agent setup screens · id.org.ai', styles: ['gallery.css'] })
})

/**
 * 19a with Stripe's real Payment Element, for matching it to the card by eye. Dev only, and only
 * when STRIPE_PUBLISHABLE_KEY (a test key, `pk_test_…`) is passed to `wrangler dev`: the key is
 * never in the repo. No intent is created and nothing can be charged.
 */
galleryRoutes.get('/__design/19a-stripe-live', async (c, next) => {
  const key = (c.env as unknown as Record<string, string | undefined>).STRIPE_PUBLISHABLE_KEY
  if (!enabled(c.env) || !key?.startsWith('pk_test_')) return next()
  const props = paymentProps.payAdd
  const live = { ...props, blocks: props.blocks.map((b) => (b.kind === 'stripe' ? { ...b, stripe: { publishableKey: key, mode: 'setup' as const } } : b)) }
  return renderPage(c, <AgentCard {...live} />, { title: 'Add a payment method (live Stripe fields) · id.org.ai', scripts: ['stripe-fields.js'], stripe: true })
})

/** A manifest entry may share another screen's fixture (`renders`); none does now that the phone drawings are unlisted. */
const SHARED = Object.fromEntries(AGENT_SCREENS.filter((s) => s.renders).map((s) => [s.slug, fixtureSlug(s)]))

galleryRoutes.get('/__design/:slug', async (c, next) => {
  if (!enabled(c.env)) return next()
  const slug = c.req.param('slug')
  const f = fixtures[SHARED[slug] ?? slug]
  if (!f) return c.notFound()
  const state = c.req.query('state')
  const variant: Variant | undefined = state ? (f.states[state] ?? f.derived[state]) : f.default
  if (!variant) return c.notFound()
  if (f.document === 'email') {
    // An email fixture renders its whole preview document (frame + template); inline styles allowed here only.
    return new Response('<!doctype html>' + String(await variant.render()), { headers: securityHeaders(EMAIL_PREVIEW_CSP) })
  }
  return renderPage(c, variant.render(), { title: variant.title, scripts: f.scripts, frozen: true })
})
