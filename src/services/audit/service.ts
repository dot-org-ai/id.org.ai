/**
 * AuditService — thin service wrapper around AuditLog
 *
 * Adds Result<T, E> typing for validation errors on log(),
 * while query() returns AuditQueryResult directly (throws on infra failure).
 * logFireAndForget() swallows all errors silently.
 */

import { AuditLog } from '../../audit'
import type { AuditEvent, AuditQueryOptions, AuditQueryResult, StoredAuditEvent } from '../../audit'
import { Ok, Err } from '../../foundation/result'
import type { Result } from '../../foundation/result'
import { ValidationError } from '../../foundation/errors'
import type { StorageAdapter } from '../../storage'

// ============================================================================
// Interface
// ============================================================================

export interface AuditService {
  log(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<Result<StoredAuditEvent, ValidationError>>
  query(options: AuditQueryOptions): Promise<AuditQueryResult>
  logFireAndForget(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<void>
}

// ============================================================================
// Implementation
// ============================================================================

export class AuditServiceImpl implements AuditService {
  private auditLog: AuditLog

  constructor({ storage }: { storage: StorageAdapter }) {
    this.auditLog = new AuditLog(storage)
  }

  async log(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<Result<StoredAuditEvent, ValidationError>> {
    if (!event.event?.trim()) {
      return Err(new ValidationError('event', 'Event name must not be empty'))
    }

    const stored = await this.auditLog.log(event)
    return Ok(stored)
  }

  async query(options: AuditQueryOptions = {}): Promise<AuditQueryResult> {
    return this.auditLog.query(options)
  }

  async logFireAndForget(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<void> {
    try {
      await this.auditLog.log(event)
    } catch {
      // swallow silently
    }
  }
}
