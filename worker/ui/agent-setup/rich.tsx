import type { JSX } from 'hono/jsx/jsx-runtime'
import { Em, Link } from '../components'

/** Text with names highlighted and links, so fixtures stay plain data. */
export type RichPart = string | { em: string } | { href: string; label: string }
export type Rich = string | RichPart[]

export function rich(text: Rich): JSX.Element {
  const parts = typeof text === 'string' ? [text] : text
  return (
    <>
      {parts.map((p) => {
        if (typeof p === 'string') return p
        if ('em' in p) return <Em>{p.em}</Em>
        return <Link href={p.href}>{p.label}</Link>
      })}
    </>
  )
}

/** The plain words of a Rich text (document titles, spoken labels). */
export function plain(text: Rich): string {
  if (typeof text === 'string') return text
  return text.map((p) => (typeof p === 'string' ? p : 'em' in p ? p.em : p.label)).join('')
}
