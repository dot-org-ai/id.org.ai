/**
 * Email polling helper for E2E tests.
 *
 * Queries ClickHouse directly for emails received via the .do/email worker.
 * Emails arrive via Cloudflare Email Routing → email worker → ClickHouse (platform.events).
 *
 * Requires CLICKHOUSE_URL, CLICKHOUSE_USER, CLICKHOUSE_PASSWORD env vars
 * (loaded automatically from .do/db/.env via vitest.config.ts).
 */

export interface ReceivedEmail {
  id: string
  sender: string
  recipient: string
  subject: string
  text: string
  html: string
  ts: string
}

function getClickHouseConfig() {
  const url = process.env.CLICKHOUSE_URL
  const user = process.env.CLICKHOUSE_USERNAME || process.env.CLICKHOUSE_USER || 'default'
  const password = process.env.CLICKHOUSE_PASSWORD
  if (!url || !password) {
    throw new Error('ClickHouse credentials not found. Ensure .do/db/.env exists with CLICKHOUSE_URL, CLICKHOUSE_USERNAME, CLICKHOUSE_PASSWORD.')
  }
  return { url, user, password }
}

async function queryClickHouse<T>(sql: string): Promise<T[]> {
  const { url, user, password } = getClickHouseConfig()
  const res = await fetch(`${url}/?default_format=JSON`, {
    method: 'POST',
    headers: {
      'X-ClickHouse-User': user,
      'X-ClickHouse-Key': password,
    },
    body: sql,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`ClickHouse query failed (${res.status}): ${text.slice(0, 300)}`)
  }
  const json = (await res.json()) as { data: T[] }
  return json.data
}

/**
 * Poll for the latest email at a given address.
 * Returns once an email arrives that was received after `afterTs`.
 */
export async function waitForEmail(address: string, opts?: { timeoutMs?: number; afterTs?: number; pollMs?: number }): Promise<ReceivedEmail> {
  const timeout = opts?.timeoutMs ?? 60_000
  const pollInterval = opts?.pollMs ?? 3_000
  const start = Date.now()

  // Determine tenant from email domain: for emails.do → 'default', for sub.emails.do → 'sub'
  const domain = address.split('@')[1] || ''
  const parts = domain.split('.')
  const tenant = parts.length > 2 ? parts[0] : 'default'

  const afterCH = opts?.afterTs
    ? new Date(opts.afterTs).toISOString().replace('T', ' ').replace('Z', '').slice(0, 23)
    : null
  const afterFilter = afterCH ? `AND ts > toDateTime64('${afterCH}', 3)` : 'AND ts > now() - INTERVAL 10 MINUTE'

  while (Date.now() - start < timeout) {
    try {
      const sql = `
        SELECT
          id,
          data.sender as sender,
          data.recipient as recipient,
          data.subject as subject,
          data.text as text,
          data.html as html,
          ts
        FROM platform.events
        WHERE type = 'email.received'
          AND ns = '${tenant}'
          AND toString(data.recipient) = '${address}'
          ${afterFilter}
        ORDER BY ts DESC
        LIMIT 1
      `
      const rows = await queryClickHouse<ReceivedEmail>(sql)
      if (rows.length > 0) return rows[0]
    } catch (err) {
      console.warn('[email] Query error (retrying):', (err as Error).message?.slice(0, 100))
    }
    await new Promise((r) => setTimeout(r, pollInterval))
  }

  throw new Error(`No email received at ${address} within ${timeout}ms`)
}

/**
 * Extract a 6-digit verification code from email text body.
 */
export function extractVerificationCode(text: string): string | null {
  const match = text.match(/\b(\d{6})\b/)
  return match ? match[1] : null
}

/**
 * Extract magic link URL from a WorkOS magic link email HTML body.
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
export async function listEmails(address: string, limit = 10): Promise<ReceivedEmail[]> {
  const domain = address.split('@')[1] || ''
  const parts = domain.split('.')
  const tenant = parts.length > 2 ? parts[0] : 'default'

  const sql = `
    SELECT
      id,
      data.sender as sender,
      data.recipient as recipient,
      data.subject as subject,
      data.text as text,
      data.html as html,
      ts
    FROM platform.events
    WHERE type = 'email.received'
      AND ns = '${tenant}'
      AND toString(data.recipient) = '${address}'
    ORDER BY ts DESC
    LIMIT ${limit}
  `
  return queryClickHouse<ReceivedEmail>(sql)
}
