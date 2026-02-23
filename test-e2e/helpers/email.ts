/**
 * Email polling helper for E2E tests.
 *
 * Uses the .do/email worker HTTP API to retrieve emails
 * sent to catch-all addresses on emails.do.
 */

const EMAIL_BASE = process.env.EMAIL_URL || 'https://email.dotdo.workers.dev'

export interface ReceivedEmail {
  id: string
  sender: string
  recipient: string
  subject: string
  text_body: string
  html_body: string
  email_date: string
  tenant: string
  time: string
}

/**
 * Poll for the latest email at a given address.
 * Returns once an email arrives that was received after `afterTs`.
 */
export async function waitForEmail(
  address: string,
  opts?: { timeoutMs?: number; afterTs?: number; pollMs?: number },
): Promise<ReceivedEmail> {
  const timeout = opts?.timeoutMs ?? 60_000
  const pollInterval = opts?.pollMs ?? 3_000
  const start = Date.now()

  while (Date.now() - start < timeout) {
    try {
      const res = await fetch(`${EMAIL_BASE}/latest/${encodeURIComponent(address)}`)
      if (res.ok) {
        const email = (await res.json()) as ReceivedEmail
        // Only return emails received after our test started
        if (!opts?.afterTs || new Date(email.email_date).getTime() > opts.afterTs) {
          return email
        }
      }
    } catch {
      // Network error — retry
    }
    await new Promise((r) => setTimeout(r, pollInterval))
  }

  throw new Error(`No email received at ${address} within ${timeout}ms`)
}

/**
 * Extract magic link URL from a WorkOS magic link email HTML body.
 * WorkOS emails contain a link to api.workos.com for magic link authentication.
 */
export function extractMagicLink(html: string): string {
  // WorkOS magic link emails contain a URL like https://api.workos.com/...
  const match = html.match(/href="(https:\/\/[^"]*workos[^"]*)"/)
  if (match) return match[1]

  // Fallback: look for any authentication-related link
  const fallback = html.match(/href="(https:\/\/[^"]*(?:magic|verify|auth|login|confirm)[^"]*)"/)
  if (fallback) return fallback[1]

  throw new Error('No magic link found in email HTML')
}

/**
 * List recent emails for an address.
 */
export async function listEmails(address: string, limit = 10): Promise<{ count: number; emails: ReceivedEmail[] }> {
  const res = await fetch(`${EMAIL_BASE}/list/${encodeURIComponent(address)}?limit=${limit}`)
  if (!res.ok) throw new Error(`Failed to list emails: ${res.status}`)
  return res.json() as Promise<{ count: number; emails: ReceivedEmail[] }>
}
