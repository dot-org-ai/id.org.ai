/**
 * identifiers.ts — pure identifier validation + Digital Link path parsing.
 *
 * HAND-PORTED (intentional fork, by-copy not by-gate) from
 * barcoding.dev/engine/src/core/check.js (mod10Verify + vinVerify) and the
 * leftmost-primary-key parsing logic of .../core/dl.js (parseDlUri). This is a
 * SMALL LOCAL CHECK, deliberately NOT:
 *   - the npm `barcoding.dev` package (pulls zxing WASM + full AI tables — too
 *     heavy for an identity worker), nor
 *   - engine-lite.js (site-coupled).
 *
 * DRIFT: no automated gate against upstream check.js/dl.js (unlike axp-faces'
 * `vendor --check`). Tracked as a bd model-gap issue.
 *
 * STAGE-1 SCOPE: handles only the /01 (GTIN) primary key with an optional /21
 * (serial) qualifier, plus the bare 17-char VIN. LGTIN(01+10), SSCC(00),
 * GIAI(8004), GRAI(8003), compressed DL, and the full qualifier taxonomy are
 * deferred + ticketed (ADR 0001 D1).
 *
 * Zero-dependency, Workers-safe.
 */

// ── GS1 mod-10 (GenSpecs §7.9) ────────────────────────────────────────────

/** GS1 mod-10 check digit: digits WITHOUT the check digit, right-anchored ×3/×1. */
export function mod10CheckDigit(body: string): number {
  let sum = 0
  const digits = body.split('').reverse()
  for (let i = 0; i < digits.length; i++) {
    const d = digits[i].charCodeAt(0) - 48
    sum += d * (i % 2 === 0 ? 3 : 1)
  }
  return (10 - (sum % 10)) % 10
}

export interface Mod10Result {
  pass: boolean
  expected: number
  got: number
  algorithm: string
}

/**
 * Verify a full GS1 numeric string (last digit = check). Callers should first
 * confirm the value is all-digits and a valid GTIN length (8/12/13/14).
 */
export function mod10Verify(full: string): Mod10Result {
  const body = full.slice(0, -1)
  const got = Number(full.slice(-1))
  const expected = mod10CheckDigit(body)
  return { pass: expected === got, expected, got, algorithm: 'GS1 mod-10 (GenSpecs §7.9)' }
}

/** GTIN grammar: all-digits, length 8/12/13/14. */
export function isGtinShape(value: string): boolean {
  return /^[0-9]+$/.test(value) && [8, 12, 13, 14].includes(value.length)
}

// ── VIN ISO 3779 / 49 CFR 565.15 ──────────────────────────────────────────

const VIN_TRANSLIT: Record<string, number> = {
  A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8,
  J: 1, K: 2, L: 3, M: 4, N: 5, P: 7, R: 9,
  S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9,
}
const VIN_WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2]

export interface VinResult {
  pass: boolean
  expected: string | null
  got: string
  algorithm: string
  /** The offending character when the VIN carries a value outside the VIN alphabet (I/O/Q or symbols). */
  charsetFail?: string
}

/**
 * VIN grammar: exactly 17 chars, VIN alphabet only (no I, O, or Q; digits and
 * A–Z minus those). This is the CONFORMANCE gate, checked before the mod-11
 * check digit (CHECKSUM_FAIL).
 */
export function isVinShape(value: string): boolean {
  return /^[A-HJ-NPR-Z0-9]{17}$/.test(value.toUpperCase())
}

/** VIN ISO 3779 / 49 CFR 565.15 check digit (position 9, index 8). */
export function vinVerify(vin: string): VinResult {
  const v = vin.toUpperCase()
  let sum = 0
  for (let i = 0; i < 17; i++) {
    const c = v[i]
    const val = c >= '0' && c <= '9' ? c.charCodeAt(0) - 48 : VIN_TRANSLIT[c]
    if (val === undefined) {
      return {
        pass: false,
        expected: null,
        got: v[8],
        algorithm: 'ISO 3779 / 49 CFR 565.15 mod-11',
        charsetFail: c,
      }
    }
    sum += val * VIN_WEIGHTS[i]
  }
  const rem = sum % 11
  const expected = rem === 10 ? 'X' : String(rem)
  const got = v[8]
  return { pass: expected === got, expected, got, algorithm: 'ISO 3779 / 49 CFR 565.15 mod-11' }
}

// ── Digital Link path parsing (leftmost primary key) ──────────────────────

/**
 * The minimal stage-1 DL path form this resolver accepts.
 * `keyAi` is always '01' here; `qualifiers` carries the optional 21 (serial).
 * Unknown trailing AIs are tolerated (never parsed as data) per the DL URI
 * Syntax "URI stem may carry extra path" allowance, but do not change grain.
 */
export interface DlPath {
  keyAi: '01'
  gtin: string
  /** Ordered qualifier AI→value pairs recognised in stage 1 (only 21). */
  qualifiers: Array<{ ai: string; value: string }>
  /** The instance serial when a /21 qualifier is present. */
  serial?: string
  /** True when an unrecognised trailing AI pair was present and ignored. */
  toleratedExtra: boolean
}

export type DlParseError = { error: 'CONFORMANCE'; message: string; hint: string }

/**
 * Parse the already-split path segments AFTER the primary key.
 * `segs` is the full ordered segment list starting at the primary key AI, e.g.
 * ['01','09506000134352'] or ['01','09506000134352','21','XYZ'].
 *
 * Returns a DlPath or a typed CONFORMANCE error. Does NOT run the mod-10 check
 * (the route does that so it can emit CHECKSUM_FAIL distinctly).
 */
export function parseDlPath(segs: string[]): DlPath | DlParseError {
  if (segs.length < 2 || segs[0] !== '01') {
    return {
      error: 'CONFORMANCE',
      message: `expected a Digital Link primary key /01/{gtin}; got /${segs.join('/')}`,
      hint: 'stage 1 resolves /01/{gtin} and /01/{gtin}/21/{serial} (and /vin/{vin})',
    }
  }
  const gtin = segs[1]
  if (!isGtinShape(gtin)) {
    return {
      error: 'CONFORMANCE',
      message: `GTIN value "${gtin}" is not 8/12/13/14 digits`,
      hint: 'a GTIN is all-numeric and 8, 12, 13, or 14 digits long (GenSpecs §3)',
    }
  }

  const qualifiers: Array<{ ai: string; value: string }> = []
  let serial: string | undefined
  let toleratedExtra = false

  // Walk remaining AI/value pairs. Only /21 (serial) is a stage-1 qualifier;
  // everything else is tolerated but ignored (grain unchanged).
  const rest = segs.slice(2)
  if (rest.length % 2 !== 0) {
    return {
      error: 'CONFORMANCE',
      message: `dangling Digital Link segment after /01/${gtin}: /${rest.join('/')}`,
      hint: 'Digital Link path AIs ride as /{ai}/{value} pairs',
    }
  }
  for (let i = 0; i < rest.length; i += 2) {
    const ai = rest[i]
    const value = rest[i + 1]
    if (ai === '21') {
      serial = value
      qualifiers.push({ ai, value })
    } else {
      toleratedExtra = true
    }
  }

  return { keyAi: '01', gtin, qualifiers, serial, toleratedExtra }
}
