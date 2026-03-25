import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import { IdProvider } from '../src/provider'
import { useContext } from 'react'
import { IdAuthContext } from '../src/context'

const mockUser = {
  id: 'user_1',
  email: 'test@test.com',
  firstName: 'Test',
  lastName: 'User',
  profilePictureUrl: null,
  emailVerified: true,
  organizationId: 'org_1',
  role: 'member',
  permissions: [],
  createdAt: '2026-01-01T00:00:00Z',
  updatedAt: '2026-01-01T00:00:00Z',
}

function TestConsumer() {
  const ctx = useContext(IdAuthContext)
  if (!ctx) return <div>no context</div>
  if (ctx.isLoading) return <div>loading</div>
  if (ctx.user) return <div>user: {ctx.user.firstName}</div>
  return <div>not authenticated</div>
}

describe('IdProvider', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
    Object.defineProperty(window, 'location', {
      value: { origin: 'https://app.com', pathname: '/', search: '', href: 'https://app.com/' },
      writable: true,
    })
  })

  it('renders children and fetches session on mount', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({ user: mockUser, organizationId: 'org_1' }),
    }))

    render(
      <IdProvider clientId="app_test">
        <TestConsumer />
      </IdProvider>
    )

    expect(screen.getByText('loading')).toBeInTheDocument()
    await waitFor(() => expect(screen.getByText('user: Test')).toBeInTheDocument())
  })

  it('shows not authenticated on 401', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 401 }))

    render(
      <IdProvider clientId="app_test">
        <TestConsumer />
      </IdProvider>
    )

    await waitFor(() => expect(screen.getByText('not authenticated')).toBeInTheDocument())
  })

  it('sets error state on network failure', async () => {
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network down')))

    function ErrorConsumer() {
      const ctx = useContext(IdAuthContext)
      if (!ctx) return <div>no context</div>
      if (ctx.error) return <div>error: {ctx.error.message}</div>
      if (ctx.isLoading) return <div>loading</div>
      return <div>ok</div>
    }

    render(
      <IdProvider clientId="app_test">
        <ErrorConsumer />
      </IdProvider>
    )

    await waitFor(() => expect(screen.getByText('error: Network down')).toBeInTheDocument())
  })
})
