/**
 * Fire-and-forget audit event logger for worker routes.
 *
 * Writes an audit event to the identity's Durable Object storage via RPC.
 * This is intentionally fire-and-forget: audit logging MUST NEVER break
 * the primary request flow.
 */
import type { IdentityStub } from '../../src/server/do/Identity'
import type { StoredAuditEvent } from '../../src/sdk/audit'

export async function logAuditEvent(
  stub: IdentityStub,
  event: {
    event: string
    actor?: string
    target?: string
    ip?: string
    userAgent?: string
    metadata?: Record<string, unknown>
  },
): Promise<void> {
  try {
    const timestamp = new Date().toISOString()
    const suffix = crypto.randomUUID().slice(0, 8)
    const key = `audit:${timestamp}:${event.event}:${suffix}`
    await stub.writeAuditEvent(key, { ...event, timestamp, key } as StoredAuditEvent)
  } catch {
    // Fire-and-forget: audit logging should never break the primary flow
  }
}
