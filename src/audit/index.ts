/**
 * Audit Log for id.org.ai
 *
 * Records security-sensitive events in Durable Object storage.
 * Every mutation, authentication attempt, and security event is logged
 * for compliance, debugging, and forensic analysis.
 *
 * Storage key format: audit:{timestamp}:{event}:{randomSuffix}
 * This ensures chronological ordering when using DO storage.list({ prefix: 'audit:' })
 *
 * Events are immutable — once written, they are never modified or deleted.
 * This aligns with the "Immutability as Trust" design principle.
 */

// ============================================================================
// Types
// ============================================================================

export interface AuditEvent {
  /** Event name, e.g. 'identity.created', 'claim.completed', 'auth.failed' */
  event: string
  /** Who performed the action (identity ID, 'anonymous', or 'system') */
  actor?: string
  /** What was acted upon (identity ID, key ID, session token prefix, etc.) */
  target?: string
  /** Request IP address */
  ip?: string
  /** Request user agent */
  userAgent?: string
  /** Additional context-specific metadata */
  metadata?: Record<string, unknown>
  /** ISO 8601 timestamp — set automatically if not provided */
  timestamp: string
}

export interface StoredAuditEvent extends AuditEvent {
  /** Storage key used to persist this event */
  key: string
}

export interface AuditQueryOptions {
  /** Filter by event name prefix (e.g. 'auth.' matches 'auth.failed', 'auth.success') */
  eventPrefix?: string
  /** Filter by actor */
  actor?: string
  /** Return events after this ISO 8601 timestamp */
  after?: string
  /** Return events before this ISO 8601 timestamp */
  before?: string
  /** Maximum number of events to return (default 50, max 200) */
  limit?: number
  /** Cursor for pagination (the storage key of the last event in previous page) */
  cursor?: string
}

export interface AuditQueryResult {
  events: StoredAuditEvent[]
  total: number
  hasMore: boolean
  cursor?: string
}

// ============================================================================
// Well-known audit event names
// ============================================================================

export const AUDIT_EVENTS = {
  // Identity lifecycle
  IDENTITY_CREATED: 'identity.created',
  IDENTITY_FROZEN: 'identity.frozen',

  // Claim flow
  CLAIM_INITIATED: 'claim.initiated',
  CLAIM_COMPLETED: 'claim.completed',
  CLAIM_FAILED: 'claim.failed',
  CLAIM_VERIFIED: 'claim.verified',

  // Authentication
  AUTH_SESSION_CREATED: 'auth.session.created',
  AUTH_SESSION_EXPIRED: 'auth.session.expired',
  AUTH_FAILED: 'auth.failed',
  AUTH_API_KEY_VALIDATED: 'auth.apikey.validated',
  AUTH_API_KEY_INVALID: 'auth.apikey.invalid',

  // Agent keys
  KEY_REGISTERED: 'key.registered',
  KEY_REVOKED: 'key.revoked',
  KEY_SIGNATURE_VERIFIED: 'key.signature.verified',
  KEY_SIGNATURE_FAILED: 'key.signature.failed',

  // Rate limiting
  RATE_LIMIT_EXCEEDED: 'rate_limit.exceeded',

  // CSRF
  CSRF_VALIDATION_FAILED: 'csrf.validation.failed',

  // OAuth
  OAUTH_CLIENT_REGISTERED: 'oauth.client.registered',
  OAUTH_CODE_ISSUED: 'oauth.code.issued',
  OAUTH_TOKEN_ISSUED: 'oauth.token.issued',
  OAUTH_TOKEN_REVOKED: 'oauth.token.revoked',
} as const

// ============================================================================
// AuditLog
// ============================================================================

/**
 * AuditLog writes and queries immutable audit events in DO storage.
 *
 * Usage:
 *   const audit = new AuditLog(ctx.storage)
 *   await audit.log({ event: 'identity.created', actor: id, target: id })
 *   const { events } = await audit.query({ limit: 50 })
 */
export class AuditLog {
  private storage: DurableObjectStorage

  constructor(storage: DurableObjectStorage) {
    this.storage = storage
  }

  /**
   * Record an audit event.
   *
   * The timestamp is set automatically to now if not provided.
   * A random suffix is appended to the key to prevent collisions
   * when multiple events occur at the same millisecond.
   */
  async log(event: Omit<AuditEvent, 'timestamp'> & { timestamp?: string }): Promise<StoredAuditEvent> {
    const timestamp = event.timestamp ?? new Date().toISOString()
    // Use a sortable timestamp prefix (pad to fixed length)
    // ISO 8601 sorts lexicographically: '2024-01-01T00:00:00.000Z'
    const suffix = crypto.randomUUID().slice(0, 8)
    const key = `audit:${timestamp}:${event.event}:${suffix}`

    const stored: StoredAuditEvent = {
      ...event,
      timestamp,
      key,
    }

    await this.storage.put(key, stored)
    return stored
  }

  /**
   * Log an event from a Request, automatically extracting IP and user-agent.
   */
  async logFromRequest(
    request: Request,
    event: Omit<AuditEvent, 'timestamp' | 'ip' | 'userAgent'> & { timestamp?: string },
  ): Promise<StoredAuditEvent> {
    const ip = request.headers.get('cf-connecting-ip')
      ?? request.headers.get('x-forwarded-for')?.split(',')[0]?.trim()
      ?? undefined
    const userAgent = request.headers.get('user-agent') ?? undefined

    return this.log({
      ...event,
      ip,
      userAgent,
    })
  }

  /**
   * Query audit events with filtering and pagination.
   *
   * Events are returned in reverse chronological order (newest first)
   * unless the storage prefix scan returns them in forward order,
   * in which case we reverse.
   */
  async query(options: AuditQueryOptions = {}): Promise<AuditQueryResult> {
    const limit = Math.min(Math.max(options.limit ?? 50, 1), 200)

    // Build the prefix for the storage scan
    let prefix = 'audit:'
    if (options.after) {
      prefix = `audit:${options.after}`
    }

    // Fetch a batch larger than needed to allow for filtering
    const fetchLimit = limit * 3 + 1
    const listOptions: { prefix: string; limit: number; start?: string; reverse?: boolean } = {
      prefix: 'audit:',
      limit: fetchLimit,
      reverse: true,
    }

    if (options.cursor) {
      // Start scanning from the cursor position (exclusive)
      listOptions.start = options.cursor
    }

    const entries = await this.storage.list<StoredAuditEvent>(listOptions)
    const allEvents: StoredAuditEvent[] = []

    for (const [key, value] of entries) {
      if (!value || typeof value !== 'object') continue

      const event = value as StoredAuditEvent
      // Ensure the key is set (in case it was stored without it)
      if (!event.key) event.key = key

      // Apply filters
      if (options.eventPrefix && !event.event.startsWith(options.eventPrefix)) continue
      if (options.actor && event.actor !== options.actor) continue
      if (options.after && event.timestamp <= options.after) continue
      if (options.before && event.timestamp >= options.before) continue

      allEvents.push(event)
    }

    // Take only the requested number
    const events = allEvents.slice(0, limit)
    const hasMore = allEvents.length > limit

    return {
      events,
      total: events.length,
      hasMore,
      cursor: hasMore && events.length > 0 ? events[events.length - 1].key : undefined,
    }
  }

  /**
   * Count audit events matching a filter.
   * Useful for rate-limit breach monitoring.
   */
  async count(options: { eventPrefix?: string; after?: string } = {}): Promise<number> {
    const entries = await this.storage.list<StoredAuditEvent>({ prefix: 'audit:' })
    let count = 0

    for (const [, value] of entries) {
      if (!value || typeof value !== 'object') continue
      const event = value as StoredAuditEvent
      if (options.eventPrefix && !event.event.startsWith(options.eventPrefix)) continue
      if (options.after && event.timestamp <= options.after) continue
      count++
    }

    return count
  }
}
