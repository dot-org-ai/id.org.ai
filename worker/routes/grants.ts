/**
 * Grants: what a Person has delegated to OAuth clients (MCP clients, apps).
 *
 *   GET  /api/grants          → { grants: [{ client_id, scopes, created_at }] }
 *   POST /api/grants/revoke   { client_id } → { revoked: true, revoked_families }
 *
 * Revoking a client's grant deletes the consent (the next authorization asks
 * the Person again) and revokes every refresh token the client holds for the
 * Person, so it can mint no new access tokens. Opaque access tokens die at
 * once; a JWT access token (api.sb) is inactive at introspection at once and,
 * at a resource server that verifies it locally, expires within 15 minutes
 * (ACCESS_TOKEN_JWT_TTL).
 *
 * Mounted after authenticateRequest (/api/*): the caller acts on their own
 * identity only. Cross-site browser POSTs are stopped by the origin check.
 */
import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import { getOAuthProvider } from './oauth'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

app.get('/api/grants', async (c) => {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  const grants = await getOAuthProvider(c).listGrants(auth.identityId)
  return c.json({ grants })
})

app.post('/api/grants/revoke', async (c) => {
  const auth = c.get('auth')
  if (!auth?.authenticated || !auth.identityId) return errorResponse(c, 401, ErrorCode.Unauthorized, 'Authentication required')
  const body = (await c.req.json().catch(() => ({}))) as { client_id?: unknown }
  if (typeof body.client_id !== 'string' || body.client_id === '' || body.client_id.length > 2048) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'client_id is required')
  }
  const result = await getOAuthProvider(c).revokeGrant(auth.identityId, body.client_id)
  return c.json({ revoked: true, ...result })
})

export { app as grantRoutes }
