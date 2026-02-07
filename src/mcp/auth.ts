/**
 * MCP Authentication for id.org.ai
 *
 * Provides three-tier authentication for MCP connections:
 *   - Level 0: No auth (anonymous, read-only)
 *   - Level 1: Session token (sandboxed, write access)
 *   - Level 2+: API key or Bearer token (claimed/production)
 *
 * Every _meta response includes the current level and upgrade instructions.
 */

export interface MCPAuthResult {
  authenticated: boolean
  identityId?: string
  level: 0 | 1 | 2 | 3
  scopes?: string[]
  capabilities?: string[]
  error?: string
  upgrade?: {
    nextLevel: number
    action: string
    url?: string
  }
}

export class MCPAuth {
  /**
   * Authenticate an MCP request.
   *
   * Returns Level 0 for unauthenticated requests (anonymous access).
   * This is the key innovation: no auth required to start using the product.
   */
  async authenticate(request: Request): Promise<MCPAuthResult> {
    // Try API key (X-API-Key or Bearer oai_*)
    const apiKey = this.extractApiKey(request)
    if (apiKey) {
      // TODO: validate against IdentityDO
      return {
        authenticated: true,
        level: 2,
        scopes: ['read', 'write'],
      }
    }

    // Try session token (Bearer ses_*)
    const sessionToken = this.extractSessionToken(request)
    if (sessionToken) {
      // TODO: validate against IdentityDO
      return {
        authenticated: true,
        level: 1,
        scopes: ['read', 'write'],
        upgrade: {
          nextLevel: 2,
          action: 'claim',
          url: 'https://id.org.ai/claim',
        },
      }
    }

    // No auth — anonymous access (Level 0)
    return {
      authenticated: false,
      level: 0,
      scopes: ['read'],
      upgrade: {
        nextLevel: 1,
        action: 'provision',
        url: 'https://id.org.ai/api/provision',
      },
    }
  }

  private extractApiKey(request: Request): string | null {
    const header = request.headers.get('x-api-key')
    if (header) return header

    const auth = request.headers.get('authorization')
    if (auth?.startsWith('Bearer oai_')) return auth.slice(7)

    return null
  }

  private extractSessionToken(request: Request): string | null {
    const auth = request.headers.get('authorization')
    if (auth?.startsWith('Bearer ses_')) return auth.slice(7)
    return null
  }
}
