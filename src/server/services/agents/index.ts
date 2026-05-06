/**
 * AgentService — first-class Agent entity under a Tenant
 *
 * Owns: Agent CRUD, lifecycle transitions, public-key reverse lookup
 * Depends on: Foundation (0), Audit (10), Identity (3 — for tenant existence)
 * Depended on by: AuthBroker (when an agent presents oai_* or agent+jwt),
 *                 future AAP wire surface (id-9s0)
 *
 * Storage keys: agent:*, agent-by-tenant:*, agent-by-pubkey:*
 */

export { AgentServiceImpl } from './service'

export type {
  AgentService,
  AgentReader,
  AgentWriter,
  Agent,
  AgentInfo,
  AgentStatus,
  AgentMode,
  RegisterAgentInput,
  RegisterAgentResult,
  UpdateAgentStatusInput,
} from './types'

export {
  DEFAULT_SESSION_TTL_MS,
  DEFAULT_MAX_LIFETIME_MS,
  DEFAULT_ABSOLUTE_LIFETIME_MS,
} from './types'
