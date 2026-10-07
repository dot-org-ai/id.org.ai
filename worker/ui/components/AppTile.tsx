import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon, type IconName } from '../icons'
import { OrgMark } from './OrgMark'
import { safeImageUrl } from './url'

/** What a 56px tile shows (components.md#app-tile-bezel, logos.md). */
export type TileContent =
  | { kind: 'org' }
  | { kind: 'monogram'; text: string }
  | { kind: 'icon'; icon: IconName }
  | { kind: 'logo'; src: string; monogram: string }

/** Monogram size: 22px for one letter, 19px for two, 20px for a dotted pair (".d"). */
function monogramClass(text: string): string {
  if (text.length <= 1) return 'id-tile id-tile--m1'
  if (text.includes('.')) return 'id-tile'
  return 'id-tile id-tile--m2'
}

export function AppTile({ content }: { content: TileContent }): JSX.Element {
  switch (content.kind) {
    case 'org':
      return (
        <div class="id-tile">
          <OrgMark size={28} />
        </div>
      )
    case 'monogram':
      return <div class={monogramClass(content.text)}>{content.text}</div>
    case 'icon':
      return (
        <div class="id-tile">
          <Icon name={content.icon} size={content.icon === 'bot' ? 26 : 24} />
        </div>
      )
    case 'logo': {
      // The client's logo_uri (https) or a first-party brand file; the monogram stands in if it fails to load (logo.ts).
      const src = safeImageUrl(content.src)
      if (!src) return <div class={monogramClass(content.monogram)}>{content.monogram}</div>
      return (
        <div class={monogramClass(content.monogram)} data-js="logo" data-monogram={content.monogram}>
          <img class="id-tile__logo" src={src} alt="" width={32} height={32} referrerpolicy="no-referrer" decoding="async" />
        </div>
      )
    }
  }
}

/** The 36px icon tile used inside wells (the SSO organisation). */
export function IconTile({ icon, text }: { icon?: IconName; text?: string }): JSX.Element {
  return <div class="id-icontile">{icon ? <Icon name={icon} size={16} /> : text}</div>
}
