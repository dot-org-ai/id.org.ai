import { describe, it, expect, vi, beforeEach } from 'vitest'
import { renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { useOrganizations } from '../src/hooks/use-organizations'
import { IdAuthContext, IdConfigContext } from '../src/context'
import type { AuthContext } from '../src/types'
import type { ReactNode } from 'react'

const mockOrgs = [
  { id: 'org_1', name: 'Acme', slug: 'acme' },
  { id: 'org_2', name: 'Globex', slug: 'globex' },
]

describe('useOrganizations', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  it('fetches organizations on mount when authenticated', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ organizations: mockOrgs }),
    }))

    const mockContext: AuthContext = {
      user: { id: 'u1', email: 'a@b.com', firstName: 'A', lastName: 'B', profilePictureUrl: null, emailVerified: true, organizationId: 'org_1', role: null, permissions: [], createdAt: '', updatedAt: '' },
      isLoading: false,
      isAuthenticated: true,
      error: null,
      signIn: vi.fn(),
      signOut: vi.fn(),
      getAccessToken: vi.fn(),
      accessToken: null,
      organizationId: 'org_1',
      permissions: [],
    }

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })

    function wrapper({ children }: { children: ReactNode }) {
      return (
        <QueryClientProvider client={qc}>
          <IdConfigContext.Provider value={{ baseUrl: 'https://id.org.ai' }}>
            <IdAuthContext.Provider value={mockContext}>{children}</IdAuthContext.Provider>
          </IdConfigContext.Provider>
        </QueryClientProvider>
      )
    }

    const { result } = renderHook(() => useOrganizations(), { wrapper })

    await waitFor(() => {
      expect(result.current.organizations).toHaveLength(2)
    })
    expect(result.current.organizations[0].slug).toBe('acme')
  })

  it('does not fetch when not authenticated', () => {
    vi.stubGlobal('fetch', vi.fn())

    const mockContext: AuthContext = {
      user: null,
      isLoading: false,
      isAuthenticated: false,
      error: null,
      signIn: vi.fn(),
      signOut: vi.fn(),
      getAccessToken: vi.fn(),
      accessToken: null,
      organizationId: null,
      permissions: [],
    }

    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })

    function wrapper({ children }: { children: ReactNode }) {
      return (
        <QueryClientProvider client={qc}>
          <IdConfigContext.Provider value={{ baseUrl: 'https://id.org.ai' }}>
            <IdAuthContext.Provider value={mockContext}>{children}</IdAuthContext.Provider>
          </IdConfigContext.Provider>
        </QueryClientProvider>
      )
    }

    renderHook(() => useOrganizations(), { wrapper })

    expect(fetch).not.toHaveBeenCalled()
  })

  it('throws when used outside provider', () => {
    expect(() => {
      renderHook(() => useOrganizations())
    }).toThrow('useOrganizations must be used within an <IdProvider>')
  })
})
