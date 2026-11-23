import type { JSX } from 'hono/jsx/jsx-runtime'

/**
 * Icons: Lucide geometry (ISC licence) at stroke-width 1.75, copied from the mocks
 * (docs/product-update/spec/icons.md). Generated from that table; keep them in sync.
 */

export type IconName =
  | 'chev_r'
  | 'chev_d'
  | 'chev_ud'
  | 'check'
  | 'key'
  | 'mail'
  | 'copy'
  | 'user'
  | 'search'
  | 'pen'
  | 'laptop'
  | 'terminal'
  | 'shield'
  | 'alert'
  | 'clock'
  | 'plus'
  | 'globe'
  | 'logout'
  | 'lock'
  | 'x'
  | 'send'
  | 'commit'
  | 'building'
  | 'bot'
  | 'external'
  | 'pause'
  | 'play'
  | 'trash'
  | 'shield_check'
  | 'card'
  | 'bank'
  | 'zap'
  | 'flask'
  | 'arrow_ur'
  | 'layers'
  | 'bell'
  | 'fingerprint'

const PATHS: Record<IconName, () => JSX.Element> = {
  // chevron-right
  chev_r: () => <><path d="m9 18 6-6-6-6" /></>,
  // chevron-down
  chev_d: () => <><path d="m6 9 6 6 6-6" /></>,
  // chevrons-up-down
  chev_ud: () => <><path d="m7 15 5 5 5-5" /><path d="m7 9 5-5 5 5" /></>,
  // check
  check: () => <><path d="M20 6 9 17l-5-5" /></>,
  // key-round
  key: () => <><path d="M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z" /><circle cx="16.5" cy="7.5" r=".5" /></>,
  // mail
  mail: () => <><rect width="20" height="16" x="2" y="4" rx="2" /><path d="m22 7-8.97 5.7a1.94 1.94 0 0 1-2.06 0L2 7" /></>,
  // copy
  copy: () => <><rect width="14" height="14" x="8" y="8" rx="2" /><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" /></>,
  // user-round
  user: () => <><circle cx="12" cy="8" r="5" /><path d="M20 21a8 8 0 0 0-16 0" /></>,
  // search
  search: () => <><circle cx="11" cy="11" r="8" /><path d="m21 21-4.3-4.3" /></>,
  // pen-line
  pen: () => <><path d="M12 20h9" /><path d="M16.376 3.622a1 1 0 0 1 3.002 3.002L7.368 18.635a2 2 0 0 1-.855.506l-2.872.838a.5.5 0 0 1-.62-.62l.838-2.872a2 2 0 0 1 .506-.854z" /></>,
  // laptop
  laptop: () => <><path d="M20 16V7a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v9m16 0H4m16 0 1.28 2.55a1 1 0 0 1-.9 1.45H3.62a1 1 0 0 1-.9-1.45L4 16" /></>,
  // terminal
  terminal: () => <><path d="m4 17 6-6-6-6" /><path d="M12 19h8" /></>,
  // shield
  shield: () => <><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /></>,
  // triangle-alert
  alert: () => <><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3" /><path d="M12 9v4" /><path d="M12 17h.01" /></>,
  // clock
  clock: () => <><circle cx="12" cy="12" r="10" /><path d="M12 6v6l4 2" /></>,
  // plus
  plus: () => <><path d="M5 12h14" /><path d="M12 5v14" /></>,
  // globe
  globe: () => <><circle cx="12" cy="12" r="10" /><path d="M12 2a14.5 14.5 0 0 0 0 20 14.5 14.5 0 0 0 0-20" /><path d="M2 12h20" /></>,
  // log-out
  logout: () => <><path d="m16 17 5-5-5-5" /><path d="M21 12H9" /><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" /></>,
  // lock
  lock: () => <><rect width="18" height="11" x="3" y="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></>,
  // x
  x: () => <><path d="M18 6 6 18" /><path d="m6 6 12 12" /></>,
  // send
  send: () => <><path d="M14.536 21.686a.5.5 0 0 0 .937-.024l6.5-19a.496.496 0 0 0-.635-.635l-19 6.5a.5.5 0 0 0-.024.937l7.93 3.18a2 2 0 0 1 1.112 1.11z" /><path d="m21.854 2.147-10.94 10.939" /></>,
  // git-commit-horizontal
  commit: () => <><circle cx="12" cy="12" r="3" /><path d="M3 12h6" /><path d="M15 12h6" /></>,
  // building
  building: () => <><rect width="16" height="20" x="4" y="2" rx="2" /><path d="M9 22v-4h6v4" /><path d="M8 6h.01" /><path d="M16 6h.01" /><path d="M12 6h.01" /><path d="M12 10h.01" /><path d="M12 14h.01" /><path d="M16 10h.01" /><path d="M16 14h.01" /><path d="M8 10h.01" /><path d="M8 14h.01" /></>,
  // bot
  bot: () => <><path d="M12 8V4H8" /><rect width="16" height="12" x="4" y="8" rx="2" /><path d="M2 14h2" /><path d="M20 14h2" /><path d="M15 13v2" /><path d="M9 13v2" /></>,
  // external-link
  external: () => <><path d="M15 3h6v6" /><path d="M10 14 21 3" /><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" /></>,
  // pause
  pause: () => <><rect x="14" y="4" width="4" height="16" rx="1" /><rect x="6" y="4" width="4" height="16" rx="1" /></>,
  // play
  play: () => <><path d="M6 3l14 9-14 9z" /></>,
  // trash-2
  trash: () => <><path d="M3 6h18" /><path d="M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6" /><path d="M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2" /><path d="M10 11v6" /><path d="M14 11v6" /></>,
  // shield-check
  shield_check: () => <><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z" /><path d="m9 12 2 2 4-4" /></>,
  // credit-card
  card: () => <><rect width="20" height="14" x="2" y="5" rx="2" /><path d="M2 10h20" /></>,
  // landmark
  bank: () => <><path d="M10 18v-7" /><path d="M11.12 2.198a2 2 0 0 1 1.76.006l7.866 3.847c.476.233.31.949-.22.949H3.474c-.53 0-.695-.716-.22-.949z" /><path d="M14 18v-7" /><path d="M18 18v-7" /><path d="M3 22h18" /><path d="M6 18v-7" /></>,
  // zap
  zap: () => <><path d="M4 14a1 1 0 0 1-.78-1.63l9.9-10.2a.5.5 0 0 1 .86.46l-1.92 6.02A1 1 0 0 0 13 10h7a1 1 0 0 1 .78 1.63l-9.9 10.2a.5.5 0 0 1-.86-.46l1.92-6.02A1 1 0 0 0 11 14z" /></>,
  // flask-conical
  flask: () => <><path d="M10 2v7.527a2 2 0 0 1-.211.896L4.72 20.55a1 1 0 0 0 .9 1.45h12.76a1 1 0 0 0 .9-1.45l-5.069-10.127A2 2 0 0 1 14 9.527V2" /><path d="M8.5 2h7" /><path d="M7 16h10" /></>,
  // arrow-up-right
  arrow_ur: () => <><path d="M7 7h10v10" /><path d="M7 17 17 7" /></>,
  // layers
  layers: () => <><path d="M12.83 2.18a2 2 0 0 0-1.66 0L2.6 6.08a1 1 0 0 0 0 1.83l8.58 3.91a2 2 0 0 0 1.66 0l8.58-3.9a1 1 0 0 0 0-1.83z" /><path d="M2 12a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 12" /><path d="M2 17a1 1 0 0 0 .58.91l8.6 3.91a2 2 0 0 0 1.65 0l8.58-3.9A1 1 0 0 0 22 17" /></>,
  // bell
  bell: () => <><path d="M10.268 21a2 2 0 0 0 3.464 0" /><path d="M3.262 15.326A1 1 0 0 0 4 17h16a1 1 0 0 0 .74-1.673C19.41 13.956 18 12.499 18 8A6 6 0 0 0 6 8c0 4.499-1.411 5.956-2.738 7.326" /></>,
  // fingerprint
  fingerprint: () => <><path d="M12 10a2 2 0 0 0-2 2c0 1.02-.1 2.51-.26 4" /><path d="M14 13.12c0 2.38 0 6.38-1 8.88" /><path d="M17.29 21.02c.12-.6.43-2.3.5-3.02" /><path d="M2 12a10 10 0 0 1 18-6" /><path d="M2 16h.01" /><path d="M21.8 16c.2-2 .131-5.354 0-6" /><path d="M5 19.5C5.5 18 6 15 6 12a6 6 0 0 1 .34-2" /><path d="M8.65 22c.21-.66.45-1.32.57-2" /><path d="M9 6.8a6 6 0 0 1 9 5.2v2" /></>,
}

export interface IconProps {
  name: IconName
  /** Rendered width and height in px. */
  size: number
  /** Extra class names (colour, margins); the icon itself never carries inline styles. */
  class?: string
}

/** A 24-unit Lucide icon at stroke-width 1.75, decorative (aria-hidden). */
export function Icon({ name, size, class: className }: IconProps): JSX.Element {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      stroke-width="1.75"
      stroke-linecap="round"
      stroke-linejoin="round"
      aria-hidden="true"
      class={className ? `id-icon ${className}` : 'id-icon'}
    >
      {PATHS[name]()}
    </svg>
  )
}
