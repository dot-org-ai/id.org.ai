import { describe, it, expect, vi } from 'vitest'
import { renderHook } from '@testing-library/react'
import { useAuth } from '../src/hooks/use-auth'
import { IdAuthContext } from '../src/context'
import type { AuthContext } from '../src/types'
import type { ReactNode } from 'react'

const mockContext: AuthContext = {
  user: { id: 'u1', email: 'a@b.com', firstName: 'A', lastName: 'B', profilePictureUrl: null, emailVerified: true, organizationId: null, role: null, permissions: ['read'], createdAt: '', updatedAt: '' },
  isLoading: false,
  isAuthenticated: true,
  error: null,
  signIn: vi.fn(),
  signOut: vi.fn(),
  getAccessToken: vi.fn().mockResolvedValue('token'),
  organizationId: null,
  permissions: ['read'],
}

function wrapper({ children }: { children: ReactNode }) {
  return <IdAuthContext.Provider value={mockContext}>{children}</IdAuthContext.Provider>
}

describe('useAuth', () => {
  it('returns context value when inside provider', () => {
    const { result } = renderHook(() => useAuth(), { wrapper })
    expect(result.current.user?.id).toBe('u1')
    expect(result.current.isAuthenticated).toBe(true)
    expect(result.current.permissions).toEqual(['read'])
  })

  it('throws when used outside provider', () => {
    expect(() => {
      renderHook(() => useAuth())
    }).toThrow('useAuth must be used within an <IdProvider>')
  })
})
