export interface AuthUser {
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

export interface Organization {
  id: string
  name: string
  slug: string
  role: string
  domains: string[]
}

export interface IdProviderProps {
  clientId: string
  baseUrl?: string
  redirectUri?: string
  onRedirectCallback?: (params: { user: AuthUser; state?: Record<string, unknown> }) => void
  children: React.ReactNode
}

export interface AuthContext {
  user: AuthUser | null
  isLoading: boolean
  isAuthenticated: boolean
  error: Error | null
  signIn: (opts?: { organizationId?: string; returnTo?: string; state?: Record<string, unknown> }) => void
  signOut: (opts?: { redirectTo?: string }) => void
  getAccessToken: () => Promise<string>
  accessToken: string | null
  organizationId: string | null
  permissions: string[]
}

export interface OrganizationsContext {
  organizations: Organization[]
  isLoading: boolean
  error: Error | null
  switchOrganization: (orgId: string) => Promise<void>
  createOrganization: (name: string) => Promise<Organization>
  isCreating: boolean
}
