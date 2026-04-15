/**
 * GitHub integration for id.org.ai
 *
 * Two components:
 *   1. GitHub App (dot-org-ai/id) — receives push webhooks, detects claim workflow files
 *   2. GitHub Action (dot-org-ai/id@v1) — runs in CI, confirms claims via OIDC
 */

export { GitHubApp } from './app'
export type { PushEvent, ClaimResult } from './app'
export { verifyClaimFromAction, requestOIDCToken, setOutput, setError, writeTenantConfig } from './action'
export type { ActionInput, ActionOutput } from './action'
