import type { CSSProperties, SVGProps } from 'react'

// The six marks of the .org.ai logo as [cx, cy, rotation]; the last is the accent, drawn in gray.
const MARKS: [number, number, number][] = [
  [20.32, 37.72, 129],
  [10.28, 27.68, 189],
  [13.96, 13.96, 249],
  [27.68, 10.28, 309],
  [37.72, 20.32, 369],
  [34.04, 34.04, 429],
]

// Each mark carries its order and its offset from the centre, for the pour in globals.css (`data-pour`).
export const OrgLogo = ({ className, ...props }: SVGProps<SVGSVGElement>) => (
  <svg
    width="48"
    height="48"
    viewBox="0 0 48 48"
    fill="none"
    xmlns="http://www.w3.org/2000/svg"
    className={className ? `org-logo ${className}` : 'org-logo'}
    {...props}
  >
    {MARKS.map(([cx, cy, deg], i) => (
      <g key={i} className="mk" style={{ '--i': i, '--dx': `${+(24 - cx).toFixed(2)}px`, '--dy': `${+(24 - cy).toFixed(2)}px` } as CSSProperties}>
        <ellipse
          cx={cx}
          cy={cy}
          rx="6.8"
          ry="3.9"
          transform={`rotate(${deg} ${cx} ${cy})`}
          fill="currentColor"
          className={i === MARKS.length - 1 ? 'fill-muted-foreground' : undefined}
        />
      </g>
    ))}
  </svg>
)
