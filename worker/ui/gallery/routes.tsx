/**
 * Design gallery: GET /__design (index) and GET /__design/:slug?state=<name>.
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
import { renderPage } from '../render'
import type { Env, Variables } from '../../types'
import { fixtures } from './fixtures'
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
  return renderPage(c, <Index />, { title: 'Design gallery · id.org.ai' })
})

galleryRoutes.get('/__design/:slug', async (c, next) => {
  if (!enabled(c.env)) return next()
  const f = fixtures[c.req.param('slug')]
  if (!f) return c.notFound()
  const state = c.req.query('state')
  const variant: Variant | undefined = state ? (f.states[state] ?? f.derived[state]) : f.default
  if (!variant) return c.notFound()
  return renderPage(c, variant.render(), { title: variant.title, scripts: f.scripts, frozen: true })
})
