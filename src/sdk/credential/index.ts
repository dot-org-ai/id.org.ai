/**
 * Credential verification SDK — org.ai ADR 0016 C5 / ADR 0018 (id-sp0).
 *
 * id.org.ai verifies and enforces; it never mints and never ingests
 * (ingest is src.do's scope, consumed through the SourcePort). The pinned
 * acceptance spec (specs/axp-acceptance.spec.json) fixes the wire shapes;
 * the verdict tier `registry-verified | holder-attested |
 * unverifiable-by-registry` is the ADR 0018 extension.
 */

export * from './types'
export * from './freshness'
export * from './verify'
export * from './gates'
export * from './sources'
