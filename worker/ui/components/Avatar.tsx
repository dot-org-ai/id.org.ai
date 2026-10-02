import type { JSX } from 'hono/jsx/jsx-runtime'

/** Up to two initials from a name ("Bryant Skarda" → "BS"); the email's first letter otherwise. */
export function initials(name: string | undefined, email?: string): string {
  const words = (name ?? '').trim().split(/\s+/).filter(Boolean)
  if (words.length >= 2) return (words[0]![0]! + words[words.length - 1]![0]!).toUpperCase()
  if (words.length === 1) return words[0]!.slice(0, 2).toUpperCase()
  return (email?.[0] ?? '?').toUpperCase()
}

/** Avatar circle: initials, or the profile photo cropped to the circle. 32px (who row) or 34px (account row). */
export function Avatar({ name, email, src, size = 32 }: { name?: string; email?: string; src?: string; size?: 32 | 34 }): JSX.Element {
  return (
    <span class={size === 34 ? 'id-avatar id-avatar--34' : 'id-avatar'} aria-hidden="true">
      {src ? <img class="id-avatar__img" src={src} alt="" width={size} height={size} referrerpolicy="no-referrer" decoding="async" /> : initials(name, email)}
    </span>
  )
}
