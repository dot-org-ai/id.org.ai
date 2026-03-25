'use client'

import type { AuthUser, Organization } from './types'

export interface SessionResponse {
  user: AuthUser | null
  organizationId: string | null
}

export function createIdClient(baseUrl: string) {
  async function fetchSession(): Promise<SessionResponse> {
    const res = await fetch(`${baseUrl}/api/session`, { credentials: 'include' })
    if (!res.ok) {
      if (res.status === 401) return { user: null, organizationId: null }
      throw new Error(`Session fetch failed: ${res.status}`)
    }
    return res.json()
  }

  async function fetchWidgetToken(): Promise<string> {
    const res = await fetch(`${baseUrl}/api/widget-token`, { credentials: 'include' })
    if (!res.ok) throw new Error(`Widget token fetch failed: ${res.status}`)
    const data = await res.json()
    return data.token
  }

  async function exchangeCode(code: string, codeVerifier: string, redirectUri: string, clientId: string): Promise<void> {
    const res = await fetch(`${baseUrl}/oauth/token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: codeVerifier,
        redirect_uri: redirectUri,
        client_id: clientId,
      }),
    })
    if (!res.ok) throw new Error(`Code exchange failed: ${res.status}`)
  }

  async function logout(): Promise<void> {
    await fetch(`${baseUrl}/api/logout`, { method: 'POST', credentials: 'include' })
  }

  async function fetchOrganizations(): Promise<Organization[]> {
    const res = await fetch(`${baseUrl}/api/organizations`, { credentials: 'include' })
    if (!res.ok) throw new Error(`Organizations fetch failed: ${res.status}`)
    const data = await res.json()
    return data.organizations
  }

  async function switchOrganization(organizationId: string): Promise<SessionResponse> {
    const res = await fetch(`${baseUrl}/api/session/organization`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ organizationId }),
    })
    if (!res.ok) throw new Error(`Organization switch failed: ${res.status}`)
    return res.json()
  }

  return { fetchSession, fetchWidgetToken, exchangeCode, logout, fetchOrganizations, switchOrganization }
}
