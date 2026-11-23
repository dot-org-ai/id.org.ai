/**
 * Where the agent setup screens link to each other: the routes HANDOFF.md
 * section 7 suggests. A proposal, not confirmed, and none of them is served
 * yet (these screens are UI only); fixtures and screens read them from here
 * so one edit moves them all.
 */
export const AGENT_ROUTES = {
  approve: (code: string) => `/agent?code=${encodeURIComponent(code)}`,
  setup: (id: string) => `/setup/${id}`,
  /** Not in the handoff's list: where "Cancel setup" goes (11f). */
  setupCancel: (id: string) => `/setup/${id}/cancel`,
  agents: '/agents',
  agentPause: (id: string) => `/agents/${id}/pause`,
  agentRemove: (id: string) => `/agents/${id}/remove`,
  agentActivity: (id: string) => `/agents/${id}/activity`,
  spending: '/spending',
  charge: (id: string) => `/spending/charges/${id}`,
  spendRules: '/spending/rules',
  paymentMethods: '/payment-methods',
  paymentMethodNew: '/payment-methods/new',
  connectPlan: (client: string) => `/connect/${client}/plan`,
  connectPay: (client: string) => `/connect/${client}/pay`,
  connectDone: (client: string) => `/connect/${client}/done`,
  /** 2a: choose account (the Switch link). */
  switchAccount: '/account/choose',
} as const
