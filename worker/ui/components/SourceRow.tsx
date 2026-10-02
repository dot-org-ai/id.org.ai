import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'
import { CopyButton } from './CopyButton'
import { KeyValue, type KV } from './KeyValue'
import { Link } from './Link'
import { httpsOnly } from './url'

export interface SourceRowProps {
  /** What's shown: the CIMD URL (without scheme), client_id, or a key fingerprint. */
  display: string
  /** Mono for keys and fingerprints. */
  mono?: boolean
  icon: 'globe' | 'key'
  details: KV[]
  /** The app's own privacy policy and terms (https only). */
  links?: { href: string; label: string }[]
  /** The full value copied. */
  copyValue: string
  copied?: boolean
}

/** Who is asking: the app's identity, expandable details, and copy (components.md#source-row-who-is-asking). */
export function SourceRow({ display, mono, icon, details, links, copyValue, copied }: SourceRowProps): JSX.Element {
  const safeLinks = (links ?? []).flatMap((l) => {
    const href = httpsOnly(l.href)
    return href ? [{ href, label: l.label }] : []
  })
  return (
    <div class="id-source">
      <details class="id-source__details" data-x>
        <summary class="id-source__summary">
          <span class="id-fg3">
            <Icon name={icon} size={16} />
          </span>
          <span class={mono ? 'id-source__value id-source__value--mono' : 'id-source__value'}>{display}</span>
          <span class="id-chev" data-chev-d>
            <Icon name="chev_d" size={14} />
          </span>
        </summary>
        <div class="id-source__panel">
          {details.map((d) => (
            <KeyValue {...d} />
          ))}
          {safeLinks.length ? (
            <div class="id-source__links">
              {safeLinks.map((l) => (
                <Link href={l.href}>{l.label}</Link>
              ))}
            </div>
          ) : null}
        </div>
      </details>
      <CopyButton value={copyValue} copied={copied} />
    </div>
  )
}
