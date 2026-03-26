# @org.ai/react

React SDK for [id.org.ai](https://id.org.ai) — Agent-First Identity.

Provides authentication, organization management, and access tokens via TanStack Query-powered hooks.

## Install

```bash
npm install @org.ai/react @tanstack/react-query react
```

## Quick Start

```tsx
import { IdProvider, useAuth, useOrganizations } from '@org.ai/react'

function App() {
  return (
    <IdProvider clientId="your_client_id">
      <YourApp />
    </IdProvider>
  )
}

function YourApp() {
  const { user, isAuthenticated, isLoading, signIn, signOut, getAccessToken } = useAuth()
  const { organizations, switchOrganization, createOrganization } = useOrganizations()

  if (isLoading) return <div>Loading...</div>
  if (!isAuthenticated) return <button onClick={() => signIn()}>Sign In</button>

  return (
    <div>
      <p>Hello {user.email}</p>
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  )
}
```

## API

### `<IdProvider>`

Wrap your app to provide auth context. Creates its own `QueryClient`.

| Prop | Type | Description |
|------|------|-------------|
| `clientId` | `string` | OAuth client ID (required) |
| `baseUrl` | `string` | API base URL (default: `https://id.org.ai`) |
| `redirectUri` | `string` | OAuth redirect URI (default: `{origin}/callback`) |
| `onRedirectCallback` | `(ctx: { user, state }) => void` | Called after successful OAuth callback |

### `useAuth()`

Returns the current auth state and actions.

```ts
const {
  user,              // AuthUser | null
  isLoading,         // boolean
  isAuthenticated,   // boolean
  error,             // Error | null
  accessToken,       // string | null (auto-refreshes before expiry)
  organizationId,    // string | null
  permissions,       // string[]
  signIn,            // (opts?) => Promise<void>
  signOut,           // (opts?) => Promise<void>
  getAccessToken,    // () => Promise<string>
} = useAuth()
```

**`signIn` options:**

```ts
signIn({
  organizationId: 'org_123',       // Pre-select organization
  returnTo: '/dashboard',          // Post-login redirect path
  state: { custom: 'data' },       // Custom state passed through OAuth flow
})
```

### `useOrganizations()`

Manage organizations for the authenticated user.

```ts
const {
  organizations,        // Organization[]
  isLoading,            // boolean
  error,                // Error | null
  switchOrganization,   // (orgId: string) => Promise<void>
  createOrganization,   // (name: string) => Promise<Organization>
  isCreating,           // boolean
} = useOrganizations()
```

Switching organizations automatically invalidates the access token and refreshes the session.

### Advanced: Direct Client

For non-hook usage (e.g., in event handlers outside React tree):

```ts
import { createIdClient } from '@org.ai/react'

const client = createIdClient('https://id.org.ai')
const session = await client.fetchSession()
const token = await client.fetchWidgetToken()
```

## Auth Flow

Uses OAuth 2.1 Authorization Code + PKCE (S256):

1. `signIn()` generates a PKCE verifier/challenge and state nonce
2. Redirects to `id.org.ai/oauth/authorize`
3. User authenticates (WorkOS AuthKit — SSO, social, MFA)
4. Redirected back with authorization code
5. `IdProvider` exchanges code for session (httpOnly cookie)
6. `useAuth()` returns the authenticated user

## Types

```ts
interface AuthUser {
  id: string
  email: string
  firstName: string | null
  lastName: string | null
  profilePictureUrl: string | null
  emailVerified: boolean
  organizationId: string | null
  role: string | null
  permissions: string[]
  createdAt: string
  updatedAt: string
}

interface Organization {
  id: string
  name: string
  slug: string
  role: string
  domains: string[]
}
```

## Requirements

- React 18+ or 19+
- `@tanstack/react-query` 5+

## License

MIT
