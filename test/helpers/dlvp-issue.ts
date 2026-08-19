/**
 * test/helpers/dlvp-issue.ts — SESSION-ONLY SD-JWT-VC issuance for DLVP tests.
 *
 * Generates ES256 / EdDSA keypairs via crypto.subtle AT TEST TIME (no live keys,
 * no real issuer secrets — RAILS), builds SD-JWT-VC issuer JWTs with `_sd`
 * disclosure digests + a `cnf` holder key, and produces key-binding JWTs. This
 * is fixture issuance ONLY — the production repo verifies presentations, it never
 * issues them (the wallet/issuance flow is DEFERRED).
 *
 * Not a *.test.ts file → not collected as a suite; imported by the DLVP tests.
 */

import { base64UrlEncode } from '../../src/sdk/oauth/pkce'
import type { JWK } from '../../src/sdk/oauth/jwt-verify'

export type FixtureAlg = 'ES256' | 'EdDSA'

export interface FixtureKey {
  alg: FixtureAlg
  privateKey: CryptoKey
  publicKey: CryptoKey
  publicJwk: JWK
}

const enc = new TextEncoder()

function b64uBytes(bytes: Uint8Array): string {
  return base64UrlEncode(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer)
}

function b64uJson(obj: unknown): string {
  return b64uBytes(enc.encode(JSON.stringify(obj)))
}

/** Generate a session keypair for the given JOSE alg and export the public JWK. */
export async function genKey(alg: FixtureAlg): Promise<FixtureKey> {
  // Inline algorithm literals so no named WebCrypto DOM type is required.
  const pair = (alg === 'ES256'
    ? await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    : await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])) as CryptoKeyPair
  const publicJwk = (await crypto.subtle.exportKey('jwk', pair.publicKey)) as unknown as JWK
  // Strip private/ops noise, keep only the public members our importer reads.
  const clean: JWK = { kty: publicJwk.kty }
  for (const k of ['crv', 'x', 'y', 'n', 'e'] as const) {
    if (publicJwk[k] !== undefined) clean[k] = publicJwk[k]
  }
  return { alg, privateKey: pair.privateKey, publicKey: pair.publicKey, publicJwk: clean }
}

/** Sign a compact JWS (header.payload.signature) with a fixture key. */
export async function signCompact(
  key: FixtureKey,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const h = b64uJson({ alg: key.alg, ...header })
  const p = b64uJson(payload)
  const data = `${h}.${p}`
  const sig =
    key.alg === 'ES256'
      ? await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, enc.encode(data))
      : await crypto.subtle.sign({ name: 'Ed25519' }, key.privateKey, enc.encode(data))
  return `${data}.${b64uBytes(new Uint8Array(sig))}`
}

/** A single object-property disclosure string: base64url([salt, name, value]). */
export function makeDisclosure(name: string, value: unknown, salt = randomSalt()): string {
  return b64uJson([salt, name, value])
}

function randomSalt(): string {
  const b = new Uint8Array(16)
  crypto.getRandomValues(b)
  return b64uBytes(b)
}

async function sha256b64u(input: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(input))
  return base64UrlEncode(d)
}

export interface IssuedSdJwt {
  issuerJwt: string
  disclosures: string[]
}

/**
 * Issue an SD-JWT-VC: every entry in `sdClaims` becomes a disclosure whose digest
 * is placed in `_sd`. `plainClaims` are placed in the clear. `cnf.jwk` binds the
 * holder key for the KB-JWT.
 */
export async function issueSdJwtVc(opts: {
  issuerKey: FixtureKey
  iss: string
  vct: string
  cnfJwk?: JWK
  sdClaims: Record<string, unknown>
  plainClaims?: Record<string, unknown>
}): Promise<IssuedSdJwt> {
  const disclosures: string[] = []
  const sd: string[] = []
  for (const [name, value] of Object.entries(opts.sdClaims)) {
    const disc = makeDisclosure(name, value)
    disclosures.push(disc)
    sd.push(await sha256b64u(disc))
  }
  const payload: Record<string, unknown> = {
    iss: opts.iss,
    vct: opts.vct,
    iat: Math.floor(Date.now() / 1000),
    _sd_alg: 'sha-256',
    _sd: sd,
    ...(opts.cnfJwk ? { cnf: { jwk: opts.cnfJwk } } : {}),
    ...(opts.plainClaims ?? {}),
  }
  const issuerJwt = await signCompact(opts.issuerKey, { typ: 'vc+sd-jwt' }, payload)
  return { issuerJwt, disclosures }
}

/** The sd_hash input: `issuer-jwt~d1~…~dN~` (trailing ~). */
export function presentationSansKb(issuerJwt: string, disclosures: string[]): string {
  return [issuerJwt, ...disclosures, ''].join('~')
}

/** Build the trailing KB-JWT (typ kb+jwt) bound to nonce/aud/sd_hash. */
export async function makeKbJwt(opts: {
  holderKey: FixtureKey
  nonce: string
  aud: string
  issuerJwt: string
  disclosures: string[]
}): Promise<string> {
  const sdHash = await sha256b64u(presentationSansKb(opts.issuerJwt, opts.disclosures))
  return signCompact(
    opts.holderKey,
    { typ: 'kb+jwt' },
    { nonce: opts.nonce, aud: opts.aud, sd_hash: sdHash, iat: Math.floor(Date.now() / 1000) },
  )
}

/** Assemble the SD-JWT combined form: issuer~d1~…~dN~[kb]. */
export function assemble(issuerJwt: string, disclosures: string[], kbJwt?: string | null): string {
  const parts = [issuerJwt, ...disclosures]
  return kbJwt ? `${parts.join('~')}~${kbJwt}` : `${parts.join('~')}~`
}

/**
 * One-call: issue an SD-JWT-VC and produce a KB-bound presentation over `nonce`
 * for `aud`. Returns the compact presentation string + the issuer public JWK
 * (for the trust map) + the raw pieces.
 */
export async function buildPresentation(opts: {
  issuerKey: FixtureKey
  holderKey: FixtureKey
  iss: string
  vct: string
  sdClaims: Record<string, unknown>
  plainClaims?: Record<string, unknown>
  nonce: string
  aud: string
}): Promise<{ presentation: string; issuerJwk: JWK; issuerJwt: string; disclosures: string[] }> {
  const issued = await issueSdJwtVc({
    issuerKey: opts.issuerKey,
    iss: opts.iss,
    vct: opts.vct,
    cnfJwk: opts.holderKey.publicJwk,
    sdClaims: opts.sdClaims,
    plainClaims: opts.plainClaims,
  })
  const kb = await makeKbJwt({
    holderKey: opts.holderKey,
    nonce: opts.nonce,
    aud: opts.aud,
    issuerJwt: issued.issuerJwt,
    disclosures: issued.disclosures,
  })
  return {
    presentation: assemble(issued.issuerJwt, issued.disclosures, kb),
    issuerJwk: opts.issuerKey.publicJwk,
    issuerJwt: issued.issuerJwt,
    disclosures: issued.disclosures,
  }
}
