import type { JSX } from 'hono/jsx/jsx-runtime'

/** The six marks of the .org.ai logo (worker/public/orgLogo.svg) as [cx, cy, rotation]; the last is the accent. */
const MARKS: [number, number, number][] = [
  [20.32, 37.72, 129],
  [10.28, 27.68, 189],
  [13.96, 13.96, 249],
  [27.68, 10.28, 309],
  [37.72, 20.32, 369],
  [34.04, 34.04, 429],
]

/**
 * The .org.ai mark, drawn in currentColor with its accent in gray. Decorative.
 * On the pages `.id-mark__accent` takes --id-fg-3; emails, which have no stylesheet, pass `accent`.
 * `pour`: the marks pour out from the centre on load and again on hover (ui.css, pour.js), as on the landing page.
 */
export function OrgMark({ size, class: className, accent: accentColor, pour }: { size: number; class?: string; accent?: string; pour?: boolean }): JSX.Element {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 48 48"
      fill="none"
      aria-hidden="true"
      class={className ? `id-mark ${className}` : 'id-mark'}
      data-js={pour ? 'pour' : undefined}
      data-pour={pour ? 'load' : undefined}
    >
      {MARKS.map(([cx, cy, deg], i) => {
        const accent = i === MARKS.length - 1
        const mark = (
          <ellipse
            cx={cx}
            cy={cy}
            rx="6.8"
            ry="3.9"
            transform={`rotate(${deg} ${cx} ${cy})`}
            fill={accent ? (accentColor ?? 'currentColor') : 'currentColor'}
            class={accent ? 'id-mark__accent' : undefined}
          />
        )
        return pour ? <g class="id-mark__mk">{mark}</g> : mark
      })}
    </svg>
  )
}
