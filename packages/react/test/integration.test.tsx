import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { IdProvider } from '../src/provider'
import { useAuth } from '../src/hooks/use-auth'
import { useOrganizations } from '../src/hooks/use-organizations'

const mockUser = {
  id: 'user_1',
  email: 'test@test.com',
  firstName: 'Test',
  lastName: 'User',
  profilePictureUrl: 'https://example.com/pic.jpg',
  emailVerified: true,
  organizationId: 'org_1',
  role: 'admin',
  permissions: ['read', 'write'],
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

const mockOrgs = [
  { id: 'org_1', name: 'Acme', slug: 'acme' },
  { id: 'org_2', name: 'Globex', slug: 'globex' },
]

function Dashboard() {
  const { user, isLoading, isAuthenticated, getAccessToken, permissions } = useAuth()
  const { organizations } = useOrganizations()

  if (isLoading) return <div>loading</div>
  if (!isAuthenticated) return <div>please sign in</div>

  return (
    <div>
      <div data-testid='user-name'>
        {user?.firstName} {user?.lastName}
      </div>
      <div data-testid='user-email'>{user?.email}</div>
      <div data-testid='org-count'>{organizations.length} orgs</div>
      <div data-testid='permissions'>{permissions.join(',')}</div>
      <button onClick={() => getAccessToken().then((t) => (document.title = t))}>get token</button>
    </div>
  )
}

describe('Integration: IdProvider + useAuth + useOrganizations', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
    Object.defineProperty(window, 'location', {
      value: { origin: 'https://app.com', pathname: '/', search: '', href: 'https://app.com/' },
      writable: true,
    })
  })

  it('full authenticated flow', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation((url: string) => {
        if (url.includes('/api/session')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ user: mockUser, organizationId: 'org_1' }),
          })
        }
        if (url.includes('/api/organizations')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ organizations: mockOrgs }),
          })
        }
        if (url.includes('/api/widget-token')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve({ token: 'wos_widget_token_abc' }),
          })
        }
        return Promise.resolve({ ok: false, status: 404 })
      }),
    )

    render(
      <IdProvider clientId='app_test' baseUrl='https://id.org.ai'>
        <Dashboard />
      </IdProvider>,
    )

    await waitFor(() => {
      expect(screen.getByTestId('user-name')).toHaveTextContent('Test User')
    })
    expect(screen.getByTestId('user-email')).toHaveTextContent('test@test.com')
    expect(screen.getByTestId('permissions')).toHaveTextContent('read,write')

    await waitFor(() => {
      expect(screen.getByTestId('org-count')).toHaveTextContent('2 orgs')
    })
  })

  it('unauthenticated flow shows sign-in prompt', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 401 }))

    render(
      <IdProvider clientId='app_test' baseUrl='https://id.org.ai'>
        <Dashboard />
      </IdProvider>,
    )

    await waitFor(() => {
      expect(screen.getByText('please sign in')).toBeInTheDocument()
    })
  })
})
