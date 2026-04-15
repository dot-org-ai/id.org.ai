/**
 * id.org.ai Database Schema
 *
 * Drizzle ORM schema for D1/SQLite.
 * This is the canonical schema for all identity data.
 *
 * NOTE: This schema is not currently wired into the runtime. The IdentityDO
 * uses Durable Object storage (ctx.storage) instead of D1. This file is
 * retained to document the intended relational schema for a future D1
 * migration. See wrangler.jsonc — the d1_databases binding has been removed.
 */

import { sqliteTable, text, integer, index, uniqueIndex } from 'drizzle-orm/sqlite-core'

// ============================================================================
// Identities — Universal identity (human/agent/service)
// ============================================================================

export const identities = sqliteTable('identities', {
  id: text('id').primaryKey(),
  type: text('type', { enum: ['human', 'agent', 'service'] }).notNull(),

  // Display
  name: text('name').notNull(),
  handle: text('handle').unique(),
  image: text('image'),
  bio: text('bio'),

  // Human fields
  email: text('email').unique(),
  emailVerified: integer('email_verified', { mode: 'boolean' }).default(false),

  // Agent fields
  agentType: text('agent_type'),
  capabilities: text('capabilities', { mode: 'json' }),
  model: text('model'),
  ownerId: text('owner_id'),

  // Capability level (0=anonymous, 1=sandboxed, 2=claimed, 3=production)
  level: integer('level').notNull().default(0),

  // Claim-by-commit
  claimToken: text('claim_token').unique(),
  claimStatus: text('claim_status', { enum: ['unclaimed', 'pending', 'claimed'] }).default('unclaimed'),
  anonymousExpiresAt: integer('anonymous_expires_at', { mode: 'timestamp' }),
  claimedAt: integer('claimed_at', { mode: 'timestamp' }),

  // GitHub identity (populated on claim)
  githubUserId: text('github_user_id'),
  githubUsername: text('github_username'),
  githubRepo: text('github_repo'),

  // Status
  status: text('status', { enum: ['active', 'frozen', 'suspended', 'deleted'] }).notNull().default('active'),
  verified: integer('verified', { mode: 'boolean' }).default(false),

  metadata: text('metadata', { mode: 'json' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  index('identities_type_idx').on(table.type),
  index('identities_email_idx').on(table.email),
  index('identities_handle_idx').on(table.handle),
  index('identities_owner_idx').on(table.ownerId),
  index('identities_claim_token_idx').on(table.claimToken),
  index('identities_github_idx').on(table.githubUserId),
  index('identities_level_idx').on(table.level),
])

// ============================================================================
// Sessions
// ============================================================================

export const sessions = sqliteTable('sessions', {
  id: text('id').primaryKey(),
  identityId: text('identity_id').notNull().references(() => identities.id, { onDelete: 'cascade' }),
  token: text('token').notNull().unique(),
  level: integer('level').notNull().default(0),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  index('sessions_identity_idx').on(table.identityId),
  index('sessions_token_idx').on(table.token),
])

// ============================================================================
// Linked Accounts
// ============================================================================

export const linkedAccounts = sqliteTable('linked_accounts', {
  id: text('id').primaryKey(),
  identityId: text('identity_id').notNull().references(() => identities.id, { onDelete: 'cascade' }),
  provider: text('provider').notNull(),
  providerAccountId: text('provider_account_id').notNull(),
  type: text('type', { enum: ['auth', 'payment', 'ai', 'platform', 'service'] }).notNull(),
  displayName: text('display_name'),
  email: text('email'),
  accessToken: text('access_token'),
  refreshToken: text('refresh_token'),
  scope: text('scope'),
  providerData: text('provider_data', { mode: 'json' }),
  status: text('status', { enum: ['active', 'pending', 'expired', 'revoked'] }).notNull().default('active'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  index('linked_accounts_identity_idx').on(table.identityId),
  uniqueIndex('linked_accounts_identity_provider_idx').on(table.identityId, table.provider, table.providerAccountId),
])

// ============================================================================
// Organizations
// ============================================================================

export const organizations = sqliteTable('organizations', {
  id: text('id').primaryKey(),
  name: text('name').notNull(),
  slug: text('slug').notNull().unique(),
  logo: text('logo'),
  verified: integer('verified', { mode: 'boolean' }).default(false),
  settings: text('settings', { mode: 'json' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
})

// ============================================================================
// Members — Identity ↔ Organization
// ============================================================================

export const members = sqliteTable('members', {
  id: text('id').primaryKey(),
  identityId: text('identity_id').notNull().references(() => identities.id, { onDelete: 'cascade' }),
  organizationId: text('organization_id').notNull().references(() => organizations.id, { onDelete: 'cascade' }),
  role: text('role').notNull().default('member'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  uniqueIndex('members_identity_org_idx').on(table.identityId, table.organizationId),
])

// ============================================================================
// API Keys
// ============================================================================

export const apiKeys = sqliteTable('api_keys', {
  id: text('id').primaryKey(),
  name: text('name'),
  key: text('key').notNull(),
  identityId: text('identity_id').notNull().references(() => identities.id, { onDelete: 'cascade' }),
  organizationId: text('organization_id').references(() => organizations.id),
  prefix: text('prefix'),
  scopes: text('scopes', { mode: 'json' }),
  expiresAt: integer('expires_at', { mode: 'timestamp' }),
  enabled: integer('enabled', { mode: 'boolean' }).default(true),
  lastUsedAt: integer('last_used_at', { mode: 'timestamp' }),
  requestCount: integer('request_count').default(0),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  index('api_keys_identity_idx').on(table.identityId),
  index('api_keys_key_idx').on(table.key),
])

// ============================================================================
// Agent Keys — Ed25519 public keys
// ============================================================================

export const agentKeys = sqliteTable('agent_keys', {
  id: text('id').primaryKey(),
  identityId: text('identity_id').notNull().references(() => identities.id, { onDelete: 'cascade' }),
  publicKey: text('public_key').notNull(),
  algorithm: text('algorithm').notNull().default('Ed25519'),
  did: text('did'),  // did:agent:ed25519:{base58pubkey}
  label: text('label'),
  revokedAt: integer('revoked_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  index('agent_keys_identity_idx').on(table.identityId),
  index('agent_keys_did_idx').on(table.did),
])

// ============================================================================
// OAuth Clients — Apps using "Login with id.org.ai"
// ============================================================================

export const oauthClients = sqliteTable('oauth_clients', {
  id: text('id').primaryKey(),
  clientId: text('client_id').notNull().unique(),
  clientSecret: text('client_secret'),
  name: text('name').notNull(),
  logo: text('logo'),
  website: text('website'),
  redirectUris: text('redirect_uris', { mode: 'json' }),
  scopes: text('scopes', { mode: 'json' }),
  grantTypes: text('grant_types', { mode: 'json' }),
  ownerId: text('owner_id').references(() => identities.id),
  disabled: integer('disabled', { mode: 'boolean' }).default(false),
  skipConsent: integer('skip_consent', { mode: 'boolean' }).default(false),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  index('oauth_clients_client_id_idx').on(table.clientId),
])

// ============================================================================
// OAuth Tokens
// ============================================================================

export const oauthAuthorizationCodes = sqliteTable('oauth_authorization_codes', {
  id: text('id').primaryKey(),
  code: text('code').notNull().unique(),
  clientId: text('client_id').notNull().references(() => oauthClients.id),
  identityId: text('identity_id').notNull().references(() => identities.id),
  redirectUri: text('redirect_uri').notNull(),
  scopes: text('scopes', { mode: 'json' }),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: text('code_challenge_method'),
  state: text('state'),
  nonce: text('nonce'),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
})

export const oauthAccessTokens = sqliteTable('oauth_access_tokens', {
  id: text('id').primaryKey(),
  token: text('token').notNull(),
  clientId: text('client_id').notNull().references(() => oauthClients.id),
  identityId: text('identity_id').references(() => identities.id),
  scopes: text('scopes', { mode: 'json' }),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
})

export const oauthRefreshTokens = sqliteTable('oauth_refresh_tokens', {
  id: text('id').primaryKey(),
  token: text('token').notNull(),
  clientId: text('client_id').notNull().references(() => oauthClients.id),
  identityId: text('identity_id').notNull().references(() => identities.id),
  scopes: text('scopes', { mode: 'json' }),
  revoked: integer('revoked', { mode: 'timestamp' }),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
})

export const oauthConsents = sqliteTable('oauth_consents', {
  id: text('id').primaryKey(),
  identityId: text('identity_id').notNull().references(() => identities.id),
  clientId: text('client_id').notNull().references(() => oauthClients.id),
  scopes: text('scopes').notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull(),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull(),
}, (table) => [
  uniqueIndex('oauth_consents_identity_client_idx').on(table.identityId, table.clientId),
])
