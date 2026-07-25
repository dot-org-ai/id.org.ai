/**
 * Credential verification surface — /credentials/* (org.ai ADR 0016 C5 /
 * ADR 0018, beads id-sp0). Validated against the pinned acceptance spec:
 *
 *   npx api.qa verify https://id.org.ai --spec specs/axp-acceptance.spec.json
 *
 * Endpoints:
 *   POST /credentials/verify              — verify(credential, principal); mode=psv answers a structured 402
 *   POST /credentials/enforce             — ordered gates: humanSigner → requiresSigner → requiresAccess
 *   GET  /credentials/gates/act/:act      — supply gate as an OBJECT with a jurisdiction (never a bool)
 *   GET  /credentials/gates/upstream/:up  — demand gate, same discipline
 *   GET  /credentials/registries          — the adapter roster (real vs honest stub, per ADR 0018 R4)
 *   GET  /credentials/registries/:id      — one registry's descriptor (ingest state, roster stats)
 *
 * Registry I/O flows through the src.do-contract SourcePort. Until the
 * src.do proxy is bound, the port answers typed `not-connected` and every
 * verification surfaces `unverifiable-by-registry` with a connect-source
 * cure — fail closed, never a fabricated pass.
 */

import { Hono } from 'hono'
import type { Env, Variables } from '../types'
import { errorResponse, ErrorCode } from '../../src/sdk/errors'
import {
  verify,
  isEffectClass,
  enforceOrdered,
  supplyGateFor,
  demandGateFor,
  REGISTRY_ADAPTERS,
  unconnectedSourcePort,
} from '../../src/sdk/credential'
import type {
  EffectClass,
  HolderPortalExport,
  PresentedCredential,
  SourcePort,
  VerificationResult,
  VerifyPrincipal,
} from '../../src/sdk/credential'
import type { HeldCredentialFact } from '../../src/server/services/credential'
import type { IdentityStub } from '../types'
import { getStubForIdentity } from '../middleware/tenant'

const app = new Hono<{ Bindings: Env; Variables: Variables }>()

// ── Port resolution ────────────────────────────────────────────────────────
// The src.do source proxy is not yet bound (its binding is the cross-repo
// dependency named in id-sp0). The unconnected port keeps every answer
// typed and fail-closed until it lands.
function sourcePort(_env: Env): SourcePort {
  return unconnectedSourcePort('src.do source proxy is not bound to id.org.ai yet')
}

function principalStub(env: Env | undefined, principalId: string): IdentityStub | null {
  if (!env || !env.IDENTITY) return null
  try {
    return getStubForIdentity(env, principalId)
  } catch {
    return null
  }
}

async function parseBody(c: { req: { json: () => Promise<unknown> } }): Promise<Record<string, unknown> | null> {
  try {
    const body = await c.req.json()
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : null
  } catch {
    return null
  }
}

function asPrincipal(v: unknown): VerifyPrincipal | null {
  if (!v || typeof v !== 'object') return null
  const p = v as { id?: unknown; workerType?: unknown }
  if (typeof p.id !== 'string' || !p.id.trim()) return null
  if (typeof p.workerType !== 'string') return null
  return p as unknown as VerifyPrincipal
}

// ── POST /credentials/verify ───────────────────────────────────────────────

app.post('/credentials/verify', async (c) => {
  const body = await parseBody(c)
  if (!body || Object.keys(body).length === 0) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'Request body must carry credential, principal, and effectClass')
  }

  // Vendor-brokered PSV is a paid mode — answer a structured 402 whose first
  // alternative is the free registry mode (pinned: B-structured-402-offer).
  if (body.mode === 'psv') {
    return c.json(
      {
        id: 'offer:psv-credential-verification',
        title: 'Vendor-brokered primary-source verification',
        price: { amount: 2.5, currency: 'USD' },
        alternatives: [
          {
            mode: 'registry',
            price: { amount: 0, currency: 'USD' },
            note: 'Free registry-lookup mode — POST /credentials/verify without mode',
          },
        ],
      },
      402,
    )
  }

  const credential = body.credential as PresentedCredential | undefined
  const principal = asPrincipal(body.principal)
  if (!credential || typeof credential.type !== 'string') {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'credential.type is required')
  }
  if (!principal) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, 'principal.id and principal.workerType are required')
  }
  if (!isEffectClass(body.effectClass)) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, "effectClass must be one of 'act' | 'record' | 'read'")
  }

  const result = await verify(credential, principal, {
    effectClass: body.effectClass,
    port: sourcePort(c.env),
    ...(body.holderAttested ? { holderAttested: body.holderAttested as HolderPortalExport } : {}),
  })
  if (!result.success) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, `${result.error.field}: ${result.error.message}`)
  }

  // Journal the verification on the principal's own DO (insert-only) —
  // best-effort: the answer never depends on the journal write.
  const stub = principalStub(c.env, principal.id)
  if (stub) {
    try {
      const v = result.data
      await stub.recordCredentialVerification({
        principalId: principal.id,
        credentialType: credential.type,
        ref: credential.registrationNumber ?? credential.licenseNumber ?? credential.membershipId ?? '',
        registry: v.source.registry,
        verdict: v.verdict,
        sourceClass: v.source.sourceClass,
        effectClass: body.effectClass,
        live: v.live,
        goodStanding: v.goodStanding,
        satisfiesActClass: v.satisfiesActClass,
        checkedAt: v.checkedAt,
      })
    } catch {
      // journal write is best-effort; the typed answer stands on its own
    }
  }

  return c.json(result.data)
})

// ── GET /credentials/registries ────────────────────────────────────────────

app.get('/credentials/registries', async (c) => {
  const port = sourcePort(c.env)
  const now = new Date()
  const registries = await Promise.all(
    Object.values(REGISTRY_ADAPTERS).map(async (adapter) => {
      if (adapter.describe) {
        try {
          return await adapter.describe({ port, now, effectClass: 'read' })
        } catch {
          // fall through to the static descriptor
        }
      }
      return {
        id: adapter.id,
        mode: adapter.mode,
        issuer: adapter.issuer,
        sourceClass: adapter.sourceClass,
        status: adapter.status,
        cadence: adapter.cadence,
      }
    }),
  )
  return c.json({ registries })
})

app.get('/credentials/registries/:id', async (c) => {
  const id = c.req.param('id')
  const adapter = REGISTRY_ADAPTERS[id]
  if (!adapter) {
    return errorResponse(c, 404, ErrorCode.NotFound, `Unknown registry '${id}'`)
  }
  const port = sourcePort(c.env)
  const descriptor = adapter.describe
    ? await adapter.describe({ port, now: new Date(), effectClass: 'read' })
    : {
        id: adapter.id,
        mode: adapter.mode,
        issuer: adapter.issuer,
        sourceClass: adapter.sourceClass,
        status: adapter.status,
        cadence: adapter.cadence,
      }
  return c.json(descriptor)
})

// ── GET /credentials/gates/* — a gate is a reference, never a bool ─────────

app.get('/credentials/gates/act/:act', (c) => {
  const act = c.req.param('act')
  const gate = supplyGateFor(act)
  if (!gate) {
    return errorResponse(c, 404, ErrorCode.NotFound, `No ratified supply gate for act '${act}'`)
  }
  return c.json(gate)
})

app.get('/credentials/gates/upstream/:upstream', (c) => {
  const upstream = c.req.param('upstream')
  const gate = demandGateFor(upstream)
  if (!gate) {
    return errorResponse(c, 404, ErrorCode.NotFound, `No ratified demand gate for upstream '${upstream}'`)
  }
  return c.json(gate)
})

// ── POST /credentials/enforce — ordered M8 → requiresSigner → requiresAccess

app.post('/credentials/enforce', async (c) => {
  const body = await parseBody(c)
  if (!body || (typeof body.act !== 'string' && typeof body.upstream !== 'string')) {
    return errorResponse(c, 400, ErrorCode.InvalidRequest, "Request must name an 'act' or an 'upstream'")
  }

  const act = typeof body.act === 'string' ? body.act : undefined
  const upstream = typeof body.upstream === 'string' ? body.upstream : undefined
  const signer = asPrincipal(body.signer) ?? undefined
  const principal = asPrincipal(body.principal) ?? undefined

  // Resolve the signer's credential evidence for the supply gate: the
  // signer's held facts (its own DO) verified fresh at act-class. A
  // holder-attested fact never clears the gate (enforceOrdered enforces it).
  let signerVerification: VerificationResult | null = null
  if (act && signer && signer.workerType === 'human') {
    const gate = supplyGateFor(act)
    if (gate) {
      const stub = principalStub(c.env, signer.id)
      let facts: HeldCredentialFact[] = []
      if (stub) {
        try {
          facts = await stub.listHeldCredentials(signer.id, gate.requiresSigner.credentialType)
        } catch {
          facts = []
        }
      }
      const port = sourcePort(c.env)
      for (const fact of facts) {
        const result = await verify(fact.presented, signer, {
          effectClass: 'act',
          port,
          ...(fact.holderAttested ? { holderAttested: fact.holderAttested } : {}),
        })
        if (!result.success) continue
        signerVerification = result.data
        if (result.data.satisfiesActClass && result.data.live && result.data.goodStanding) break
      }
    }
  }

  // Resolve the principal's entitlement for the demand gate.
  let principalEntitled = false
  if (upstream && principal) {
    const gate = demandGateFor(upstream)
    if (gate) {
      const stub = principalStub(c.env, principal.id)
      if (stub) {
        try {
          const entitlements = await stub.listHeldCredentials(principal.id, gate.requiresAccess.entitlementType)
          principalEntitled = entitlements.length > 0
        } catch {
          principalEntitled = false
        }
      }
    }
  }

  const decision = enforceOrdered({
    ...(act ? { act } : {}),
    ...(upstream ? { upstream } : {}),
    ...(signer ? { signer } : {}),
    ...(principal ? { principal } : {}),
    signerVerification,
    principalEntitled,
  })

  if (decision.denied) {
    return c.json(decision, 403)
  }
  return c.json(decision)
})

export { app as credentialRoutes }
