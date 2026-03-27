/**
 * Audit — Domain 10
 *
 * Owns: immutable audit event logging and querying
 * Depends on: Foundation (0)
 * Key types: AuditService, AuditEvent, StoredAuditEvent, AuditQueryOptions
 * Storage keys: audit:{timestamp}:{event}:{suffix}
 */

export { AuditServiceImpl } from './service'
export type { AuditService } from './service'

// Re-export types and constants from the underlying audit module
export { AUDIT_EVENTS } from '../../audit'
export type { AuditEvent, StoredAuditEvent, AuditQueryOptions, AuditQueryResult } from '../../audit'
