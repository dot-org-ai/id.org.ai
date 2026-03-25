// Types
export type { AuthUser, Organization, IdProviderProps, AuthContext, OrganizationsContext } from './types'

// Provider
export { IdProvider } from './provider'

// Hooks
export { useAuth } from './hooks/use-auth'
export { useOrganizations } from './hooks/use-organizations'

// Context (for advanced use — wrapping in custom providers)
export { IdAuthContext, IdConfigContext } from './context'

// Client (for advanced use)
export { createIdClient } from './client'
export type { SessionResponse } from './client'
