/**
 * Gallery fixtures (docs/product-update/prompts/01-foundation.md#gallery-contract).
 *
 * One fixture per manifest slug: the screen component plus its props for the
 * default render, each mocked state (`states`, names exactly as in
 * mocks/manifest.json) and each derived state with no mock (`derived`).
 * defineFixture binds props to thunks, so groups of differently-typed screens
 * share one record type without `any`.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import type { ClientScript } from '../assets'

export interface ScreenFixture<P> {
  /** The presentational screen component. */
  screen: (props: P) => JSX.Element
  /** Document title for these props, for example "Sign in · id.org.ai". */
  title: (props: P) => string
  /** Client scripts the screen loads. */
  scripts?: ClientScript[]
  /** `page` renders through renderPage; `email` through the email preview frame (no style-src). */
  document?: 'page' | 'email'
  default: P
  states?: Record<string, P>
  derived?: Record<string, P>
}

export interface Variant {
  title: string
  render: () => JSX.Element
}

export interface BoundFixture {
  scripts: ClientScript[]
  document: 'page' | 'email'
  default: Variant
  states: Record<string, Variant>
  derived: Record<string, Variant>
}

export function defineFixture<P>(f: ScreenFixture<P>): BoundFixture {
  const bind = (props: P): Variant => ({ title: f.title(props), render: () => f.screen(props) })
  const map = (rec: Record<string, P> | undefined) => Object.fromEntries(Object.entries(rec ?? {}).map(([k, p]) => [k, bind(p)]))
  return {
    scripts: f.scripts ?? [],
    document: f.document ?? 'page',
    default: bind(f.default),
    states: map(f.states),
    derived: map(f.derived),
  }
}

export type FixtureGroup = Record<string, BoundFixture>
