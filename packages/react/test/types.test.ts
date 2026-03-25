import { describe, it, expect } from 'vitest'
import type { AuthUser, Organization, IdProviderProps, AuthContext } from '../src/types'

describe('types', () => {
  it('AuthUser has WorkOS-compatible shape', () => {
    const user: AuthUser = {
      id: 'user_123',
      email: 'test@example.com',
      firstName: 'Test',
      lastName: 'User',
      profilePictureUrl: null,
      emailVerified: true,
      organizationId: 'org_123',
      role: 'member',
      permissions: ['read'],
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
    }
    expect(user.id).toBe('user_123')
    expect(user.firstName).toBe('Test')
    expect(user.profilePictureUrl).toBeNull()
  })

  it('Organization has required fields', () => {
    const org: Organization = { id: 'org_1', name: 'Acme', slug: 'acme' }
    expect(org.slug).toBe('acme')
  })

  it('AuthContext includes error field', () => {
    const ctx: AuthContext = {
      user: null,
      isLoading: true,
      isAuthenticated: false,
      error: null,
      signIn: () => {},
      signOut: () => {},
      getAccessToken: async () => '',
      organizationId: null,
    }
    expect(ctx.error).toBeNull()
  })
})
