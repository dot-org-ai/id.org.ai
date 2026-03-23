import { ImageResponse } from 'next/og'

export const dynamic = 'force-static'

export async function GET() {
  return new ImageResponse(
    (
      <div
        style={{
          height: '100%',
          width: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: '#000000',
        }}
      >
        {/* Main hero text */}
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            fontSize: '100px',
            fontWeight: 700,
            color: '#ffffff',
            lineHeight: 1.1,
            textAlign: 'center',
            letterSpacing: '-0.02em',
            marginBottom: '40px',
          }}
        >
          <span>Humans.</span>
          <span>Agents.</span>
          <span>Auth.</span>
        </div>

        {/* Tagline */}
        <div
          style={{
            fontSize: '36px',
            color: '#a1a1a1',
            textAlign: 'center',
            marginBottom: '40px',
          }}
        >
          Simple, secure sign-in for humans and AI agents
        </div>

        {/* Domain branding */}
        <div
          style={{
            fontSize: '32px',
            color: '#666666',
            fontWeight: 500,
          }}
        >
          id.org.ai
        </div>
      </div>
    ),
    {
      width: 1200,
      height: 630,
      headers: {
        'Cache-Control': 'public, immutable, no-transform, max-age=31536000',
      },
    }
  )
}
