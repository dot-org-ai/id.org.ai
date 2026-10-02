import type { JSX } from 'hono/jsx/jsx-runtime'
import { IconTile } from './AppTile'
import { NameSub } from './Who'

/**
 * An organisation inside a well (1c SSO): the 36px building tile, then the
 * name and a sub-line ("Verified domain northwind.co").
 */
export function OrgRow({ name, sub }: { name: string; sub: string }): JSX.Element {
  return (
    <div class="id-orgrow">
      <IconTile icon="building" />
      <NameSub name={name} sub={sub} />
    </div>
  )
}
