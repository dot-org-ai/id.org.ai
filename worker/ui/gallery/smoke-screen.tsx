import type { JSX } from 'hono/jsx/jsx-runtime'
import { Card, Page } from '../components'

/** Phase 1 smoke screen: the shell and an empty card. Deleted in phase 3. */
export function SmokeScreen(_props: Record<string, never>): JSX.Element {
  return (
    <Page>
      <Card>{null}</Card>
    </Page>
  )
}
