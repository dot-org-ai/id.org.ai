'use client'

export function MeshGradientBackground() {
  return (
    <div className="absolute inset-0 z-0 pointer-events-none overflow-hidden">
      {/* Top-left gradient blob */}
      <div
        className="absolute -top-[300px] -left-[300px] w-[600px] h-[600px] rounded-full blur-[100px] opacity-[0.03] dark:opacity-5"
        style={{ backgroundColor: 'var(--foreground)' }}
      />

      {/* Bottom-right gradient blob */}
      <div
        className="absolute -bottom-[300px] -right-[300px] w-[400px] h-[600px] rounded-full blur-[120px] opacity-[0.04] dark:opacity-5"
        style={{ backgroundColor: 'var(--foreground)' }}
      />

      {/* Noise texture overlay */}
      <svg className="absolute inset-0 w-full h-full mix-blend-overlay opacity-40 dark:opacity-10">
        <defs>
          <filter id="mesh-noise">
            <feTurbulence
              type="fractalNoise"
              baseFrequency="0.65"
              numOctaves="3"
              stitchTiles="stitch"
            />
          </filter>
        </defs>
        <rect width="100%" height="100%" filter="url(#mesh-noise)" />
      </svg>
    </div>
  )
}
