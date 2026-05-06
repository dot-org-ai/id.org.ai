/**
 * Identity Core — Domain 3
 *
 * Owns: Identity CRUD, provisioning, freeze/unfreeze, linked accounts
 * Depends on: Foundation (0), Audit (10), EntityStore (9)
 * Depended on by: ClaimService (4), KeysService (5), AuthService (1),
 *                 MCPService (6), OAuthService (2), OrgService (7)
 * Key types: IdentityReader, IdentityWriter, Identity, LinkedAccount
 * Storage keys: identity:*, idx:handle:*, idx:email:*, idx:github:*, linked:*
 */

export { IdentityServiceImpl } from './service'

export type {
  // Interfaces
  IdentityReader,
  IdentityWriter,

  // Domain types
  Identity,
  IdentityType,
  CapabilityLevel,
  ClaimStatus,
  LinkedAccount,
  LinkedAccountProvider,
  LinkedAccountType,
  LinkedAccountStatus,

  // Input types
  CreateIdentityInput,
  CreateIdentityResult,
  CreateHumanInput,
  CreateServiceInput,
  ProvisionTenantInput,
  ProvisionTenantResult,
  UpdateIdentityInput,
  LinkAccountInput,
} from './types'
