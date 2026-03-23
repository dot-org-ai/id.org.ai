'use client'

export function SpotlightBackground() {
  return (
    <div
      className="absolute inset-0 z-0 pointer-events-none"
      style={{
        background: `radial-gradient(ellipse 80% 60% at 50% 40%, transparent 0%, oklch(from var(--foreground) l c h / 0.04) 100%)`,
      }}
    />
  )
}
