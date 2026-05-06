/**
 * Fire-and-forget audit event logger for worker routes.
 *
 * Delegates to AuditService via the IdentityDO RPC. Fire-and-forget:
 * audit logging MUST NEVER break the primary request flow.
 */
import type { IdentityStub } from '../../src/server/do/Identity'

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
    await stub.auditEvent(event)
  } catch {
    // Fire-and-forget: audit logging should never break the primary flow
  }
}
