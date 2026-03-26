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
    const res = await fetch(`${baseUrl}/api/orgs`, { credentials: 'include' })
    if (!res.ok) throw new Error(`Organizations fetch failed: ${res.status}`)
    const data = await res.json()
    return (data.organizations as Array<{ id: string; name: string; role?: string; domains?: string[] }>).map((o) => ({
      id: o.id,
      name: o.name,
      slug: o.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
      role: o.role ?? 'member',
      domains: o.domains ?? [],
    }))
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

  async function createOrganization(name: string): Promise<Organization> {
    const res = await fetch(`${baseUrl}/api/orgs`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ name }),
    })
    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: res.statusText }))
      throw new Error((body as { error?: string }).error || `Create org failed: ${res.status}`)
    }
    const data = await res.json()
    return {
      id: data.id,
      name: data.name,
      slug: data.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, ''),
      role: 'admin',
      domains: [],
    }
  }

  return { fetchSession, fetchWidgetToken, exchangeCode, logout, fetchOrganizations, switchOrganization, createOrganization }
}
