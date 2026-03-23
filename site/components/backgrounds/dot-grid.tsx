'use client'

export function DotGridBackground() {
  return (
    <div
      className="absolute inset-0 z-0 pointer-events-none opacity-[0.07]"
      style={{
        backgroundImage: `radial-gradient(circle at center, currentColor 1px, transparent 1px)`,
        backgroundSize: '24px 24px',
      }}
    />
  )
}
