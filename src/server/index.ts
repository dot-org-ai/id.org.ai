// src/server/index.ts
// Cloudflare-specific exports — requires cloudflare:workers runtime

export { IdentityDO } from './do/Identity'
export type { Identity, IdentityType, IdentityEnv } from './do/Identity'
export { DurableObjectStorageAdapter } from './do/storage-adapter'

// Services (for direct use or testing)
export { AuditServiceImpl } from './services/audit/service'
export { EntityStoreServiceImpl } from './services/entity-store/service'
export { IdentityServiceImpl } from './services/identity/service'
export { KeyServiceImpl } from './services/keys/service'
export { SessionServiceImpl } from './services/auth/service'

// AuditLog
export { AuditLog } from '../sdk/audit'
