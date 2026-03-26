/**
 * Org picker page renderer for id.org.ai
 */
import { escapeHtml } from '../utils/html'
import type { OrgSelectionError } from '../../src/workos/upstream'

// ── Org Picker Page Renderer ────────────────────────────────────────────────
export function renderOrgPickerPage(err: OrgSelectionError, state: string): Response {
  const orgButtons = err.organizations.map((org) => `
    <button type="submit" name="organization_id" value="${escapeHtml(org.id)}"
      class="org-btn">
      <span class="org-name">${escapeHtml(org.name)}</span>
      <svg width="16" height="16" viewBox="0 0 16 16" fill="none"><path d="M6 4l4 4-4 4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/></svg>
    </button>`).join('\n')

  const userName = [err.user.first_name, err.user.last_name].filter(Boolean).join(' ') || err.user.email

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Choose Organization — id.org.ai</title>
  <style>
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
      font-family: system-ui, -apple-system, 'Segoe UI', sans-serif;
      background: #000;
      color: #fff;
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
    }
    .container {
      width: 100%;
      max-width: 420px;
      padding: 24px;
    }
    .header {
      margin-bottom: 32px;
    }
    .brand {
      font-size: 14px;
      color: #666;
      margin-bottom: 24px;
    }
    h1 {
      font-size: 28px;
      font-weight: 600;
      letter-spacing: -0.02em;
      margin-bottom: 8px;
    }
    .subtitle {
      font-size: 15px;
      color: #888;
    }
    .subtitle strong {
      color: #aaa;
      font-weight: 500;
    }
    .orgs {
      display: flex;
      flex-direction: column;
      gap: 8px;
      margin-top: 24px;
    }
    .org-btn {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding: 14px 16px;
      background: rgba(255,255,255,0.05);
      border: 1px solid rgba(255,255,255,0.1);
      border-radius: 10px;
      color: #fff;
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
      font-family: inherit;
    }
    .org-btn:hover {
      background: rgba(255,255,255,0.1);
      border-color: rgba(255,255,255,0.2);
    }
    .org-btn:active {
      background: rgba(255,255,255,0.08);
    }
    .org-btn svg {
      color: #666;
      transition: color 0.15s;
    }
    .org-btn:hover svg {
      color: #fff;
    }
    .footer {
      margin-top: 32px;
      text-align: center;
      font-size: 13px;
      color: #444;
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="brand">id.org.ai</div>
      <h1>Choose organization</h1>
      <p class="subtitle">Signed in as <strong>${escapeHtml(userName)}</strong></p>
    </div>
    <form method="POST" action="/api/org-select">
      <input type="hidden" name="pending_token" value="${escapeHtml(err.pendingAuthenticationToken)}">
      <input type="hidden" name="state" value="${escapeHtml(state)}">
      <div class="orgs">
        ${orgButtons}
      </div>
    </form>
    <div class="footer">Select the organization you want to sign in to</div>
  </div>
</body>
</html>`

  return new Response(html, {
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
  })
}
