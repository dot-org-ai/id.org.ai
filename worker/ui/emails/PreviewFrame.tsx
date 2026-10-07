/**
 * Gallery only (spec/emails.md#gallery-preview): the inbox preview frame from the
 * 8a–8c mocks (page colour, 28px padding, the From and Subject lines, 16px gap)
 * around a template, as a whole document. Never sent: it exists so the template
 * can be pixel-compared against the mock. Its styles are copied from the mock
 * verbatim, including the mock page's global body rule.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { EmailFonts, type EmailParts } from './layout'

const MOCK_BODY = 'body{margin:0;background:oklch(0.155 0.004 286);text-rendering:optimizeLegibility;-moz-osx-font-smoothing:grayscale}'

const frame = (height: number) =>
  `width: 640px; height: ${height}px; box-sizing: border-box; padding: 28px; background: oklch(0.965 0.003 286); font-family: 'Geist', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif; color: oklch(0.21 0.01 286); -webkit-font-smoothing: antialiased; display: flex; flex-direction: column; gap: 16px`
const headerStyle = 'display: flex; flex-direction: column; gap: 4px; padding: 0 4px; font-size: 13px; color: oklch(0.52 0.01 286)'
const labelStyle = 'color: oklch(0.42 0.01 286)'
const subjectStyle = 'color: oklch(0.21 0.01 286); font-weight: 600'

export interface PreviewFrameProps {
  email: EmailParts
  /** The mock's board height (8a 640, 8b 620, 8c 680). */
  height: number
}

export function PreviewFrame({ email, height }: PreviewFrameProps): JSX.Element {
  return (
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <title>{email.subject}</title>
        <EmailFonts base="" />
        <style dangerouslySetInnerHTML={{ __html: MOCK_BODY }} />
      </head>
      <body>
        <div style={frame(height)}>
          <div style={headerStyle}>
            <span>
              <span style={labelStyle}>From</span>
              {` ${email.from.name} <${email.from.email}>`}
            </span>
            <span>
              <span style={labelStyle}>Subject</span> <span style={subjectStyle}>{email.subject}</span>
            </span>
          </div>
          {email.content}
        </div>
      </body>
    </html>
  )
}
