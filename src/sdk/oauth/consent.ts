/**
 * Consent Screen Generation
 *
 * Generates a consent/approval screen for third-party OAuth clients.
 * Users see what permissions an AI agent (Claude, ChatGPT, etc.) is requesting
 * and can approve or deny access.
 *
 * Ported from @dotdo/oauth core/src/consent.ts
 */

import type { OAuthConsent } from './types'

/**
 * Human-readable scope descriptions
 */
const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'View your profile information (name, picture)',
  email: 'View your email address',
  offline_access: 'Maintain access when you are not actively using the app',
  'mcp:read': 'Read data through the Model Context Protocol',
  'mcp:write': 'Create and modify data through the Model Context Protocol',
  'mcp:admin': 'Full administrative access through the Model Context Protocol',
}

/**
 * Get a human-readable description for a scope
 */
export function getScopeDescription(scope: string): string {
  return SCOPE_DESCRIPTIONS[scope] ?? `Access: ${scope}`
}

/**
 * Check whether existing consent covers all requested scopes
 */
export function consentCoversScopes(consent: OAuthConsent, requestedScopes: string[]): boolean {
  return requestedScopes.every((scope) => consent.scopes.includes(scope))
}

/**
 * Options for generating the consent screen HTML
 */
export interface ConsentScreenOptions {
  /** Server issuer URL */
  issuer: string
  /** Client name (display name of the requesting app) */
  clientName: string
  /** Client ID */
  clientId: string
  /** Redirect URI the client wants to redirect to */
  redirectUri: string
  /** Requested scopes */
  scopes: string[]
  /** Consent token (opaque token referencing the pending auth request) */
  consentToken: string
}

/**
 * Generate the consent screen HTML
 *
 * Shows the user what permissions a third-party client is requesting
 * and provides Allow/Deny buttons.
 */
export function generateConsentScreenHtml(options: ConsentScreenOptions): string {
  const { issuer, clientName, clientId, redirectUri, scopes, consentToken } = options

  const scopeListHtml = scopes
    .map((scope) => {
      const description = getScopeDescription(scope)
      return `<li><span class="scope-name">${escapeHtml(scope)}</span><span class="scope-desc">${escapeHtml(description)}</span></li>`
    })
    .join('\n        ')

  let redirectHost = ''
  try {
    redirectHost = new URL(redirectUri).host
  } catch {
    redirectHost = redirectUri
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Authorize - ${escapeHtml(issuer)}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 20px;
    }
    .container {
      background: white;
      border-radius: 16px;
      padding: 40px;
      width: 100%;
      max-width: 480px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    }
    .header {
      text-align: center;
      margin-bottom: 32px;
    }
    .header h1 {
      font-size: 22px;
      color: #1a1a2e;
      margin-bottom: 8px;
    }
    .header p {
      color: #666;
      font-size: 14px;
      line-height: 1.5;
    }
    .client-info {
      background: #f3f4f6;
      border-radius: 12px;
      padding: 16px 20px;
      margin-bottom: 24px;
    }
    .client-name {
      font-size: 18px;
      font-weight: 600;
      color: #1f2937;
      margin-bottom: 4px;
    }
    .client-detail {
      font-size: 13px;
      color: #6b7280;
      word-break: break-all;
    }
    .scopes-section {
      margin-bottom: 28px;
    }
    .scopes-section h2 {
      font-size: 15px;
      font-weight: 600;
      color: #374151;
      margin-bottom: 12px;
    }
    .scopes-list {
      list-style: none;
      padding: 0;
    }
    .scopes-list li {
      display: flex;
      flex-direction: column;
      padding: 10px 0;
      border-bottom: 1px solid #f3f4f6;
    }
    .scopes-list li:last-child {
      border-bottom: none;
    }
    .scope-name {
      font-size: 13px;
      font-weight: 500;
      color: #1f2937;
      font-family: monospace;
      background: #eef2ff;
      padding: 2px 6px;
      border-radius: 4px;
      display: inline-block;
      margin-bottom: 4px;
      width: fit-content;
    }
    .scope-desc {
      font-size: 14px;
      color: #4b5563;
    }
    .actions {
      display: flex;
      gap: 12px;
    }
    .actions form {
      flex: 1;
    }
    .btn {
      width: 100%;
      padding: 14px 24px;
      border: none;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: transform 0.2s, box-shadow 0.2s;
    }
    .btn:hover {
      transform: translateY(-1px);
    }
    .btn:active {
      transform: translateY(0);
    }
    .btn-allow {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
    }
    .btn-allow:hover {
      box-shadow: 0 10px 20px -10px rgba(102, 126, 234, 0.5);
    }
    .btn-deny {
      background: #f3f4f6;
      color: #374151;
      border: 1px solid #d1d5db;
    }
    .btn-deny:hover {
      background: #e5e7eb;
    }
    .footer {
      text-align: center;
      margin-top: 24px;
      color: #9ca3af;
      font-size: 12px;
      line-height: 1.5;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Authorize Access</h1>
      <p>${escapeHtml(issuer)}</p>
    </div>

    <div class="client-info">
      <div class="client-name">${escapeHtml(clientName)}</div>
      <div class="client-detail">wants to access your account</div>
      <div class="client-detail" style="margin-top: 8px;">Redirect: ${escapeHtml(redirectHost)}</div>
    </div>

    <div class="scopes-section">
      <h2>This will allow the application to:</h2>
      <ul class="scopes-list">
        ${scopeListHtml}
      </ul>
    </div>

    <div class="actions">
      <form method="POST" action="/consent">
        <input type="hidden" name="consent_token" value="${escapeHtml(consentToken)}">
        <input type="hidden" name="action" value="deny">
        <button type="submit" class="btn btn-deny">Deny</button>
      </form>
      <form method="POST" action="/consent">
        <input type="hidden" name="consent_token" value="${escapeHtml(consentToken)}">
        <input type="hidden" name="action" value="allow">
        <button type="submit" class="btn btn-allow">Allow</button>
      </form>
    </div>

    <div class="footer">
      <p>You can revoke this access at any time.</p>
      <p>Client ID: ${escapeHtml(clientId)}</p>
    </div>
  </div>
</body>
</html>`
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(str: string): string {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;')
}
