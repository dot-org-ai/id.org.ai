/**
 * Audit log query route — /api/audit
 * Requires L2+ authentication.
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode, errorMessage } from '../../src/sdk/errors'
import type { AuditQueryOptions } from '../../src/sdk/audit'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.get('/api/audit', async (c) => {
  const auth = c.get('auth')
  if (!auth.authenticated || !auth.identityId) {
    return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required to query audit log')
  }
  if (auth.level < 2) {
    return errorResponse(c, 403, ErrorCode.InsufficientLevel, 'L2+ authentication required to access audit logs')
  }

  const stub = c.get('identityStub')
  if (!stub) {
    return errorResponse(c, 500, ErrorCode.ServerError, 'Identity stub not resolved')
  }

  // Build query options from URL params
  const url = new URL(c.req.url)
  const queryParams: AuditQueryOptions = {}
  if (url.searchParams.has('eventPrefix')) queryParams.eventPrefix = url.searchParams.get('eventPrefix')!
  if (url.searchParams.has('actor')) queryParams.actor = url.searchParams.get('actor')!
  if (url.searchParams.has('after')) queryParams.after = url.searchParams.get('after')!
  if (url.searchParams.has('before')) queryParams.before = url.searchParams.get('before')!
  if (url.searchParams.has('limit')) queryParams.limit = parseInt(url.searchParams.get('limit')!, 10)
  if (url.searchParams.has('cursor')) queryParams.cursor = url.searchParams.get('cursor')!

  try {
    const data = await stub.queryAuditLog(queryParams)
    return c.json(data)
  } catch (err: unknown) {
    return errorResponse(c, 500, ErrorCode.ServerError, errorMessage(err))
  }
})

export { app as auditRoutes }
