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
 * STAGE-1 SCOPE (unchanged, preserved for the shipped tests): `parseDlPath`
 * handles only the /01 (GTIN) primary key with an optional /21 (serial)
 * qualifier, plus the bare 17-char VIN.
 *
 * PHASE-4 EXPANSION (additive): `parseDlKey` generalises the leftmost-primary-key
 * parse to a KEY GRAMMAR TABLE covering 00 SSCC / 414 GLN / 8004 GIAI / 8003 GRAI
 * / 253 GDTI / 01 GTIN, each with its declared grain, value grammar (all-digit
 * or CSET-82), and check-digit rule. Path qualifiers (10 lot, 21 serial) sort in
 * canonical order (22 CPV → 10 → 21; we implement 10 → 21, 22 deferred); the 17
 * expiry AI is NOT a path qualifier — it is a DATA ATTRIBUTE that degrades to a
 * sorted query parameter (GS1 DL URI Syntax), so we validate its date grammar but
 * never treat it as a path segment that changes grain.
 *
 * DEFERRED + TICKETED (bd model-gap): compressed DL 1.1.4, the remaining primary
 * keys (255 GCN, 8010/8011 CPID, 8017/8018 GSRN, 417, 8006/8026 ITIP, 254 GLN
 * extension as a data attribute), 22 CPV, element-string↔DL conversion, and the
 * hand-port drift gate against upstream check.js/dl.js.
 *
 * Zero-dependency, Workers-safe.
 */

/**
 * The declared grain of an identifier. Mirrors `registry/port.ts` Grain (kept as
 * a local copy so this pure module stays dependency-free of the registry).
 */
export type Grain = 'class' | 'lot' | 'instance' | 'place' | 'asset' | 'document'

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

// ── CSET-82 (GS1 AI encodable character set 82, GenSpecs §7.11) ─────────────

/**
 * GS1 CSET 82: the 82 characters an alphanumeric AI value may carry —
 * A–Z a–z 0–9 and the 20 symbols `! " % & ' ( ) * + , - . / : ; < = > ? _`.
 * `-` is placed last in the class so it is literal.
 */
const CSET82 = /^[A-Za-z0-9!"%&'()*+,./:;<=>?_-]+$/

/** True iff every character of `value` is in CSET-82 and the length is in range. */
export function isCset82(value: string, min = 1, max = Infinity): boolean {
  return value.length >= min && value.length <= max && CSET82.test(value)
}

/** All-digit fixed-length grammar (SSCC/GLN and the numeric cores of GRAI/GDTI). */
function isNumericLen(value: string, len: number): boolean {
  return value.length === len && /^[0-9]+$/.test(value)
}

/**
 * GS1 expiry (AI 17) date grammar YYMMDD. MM is 01–12; DD is 00–31, where GS1
 * uses DD='00' to mean "end of month". This is a DATA ATTRIBUTE, never a path
 * qualifier — validated for grammar only.
 */
export function isExpiryDate(value: string): boolean {
  if (!/^[0-9]{6}$/.test(value)) return false
  const mm = Number(value.slice(2, 4))
  const dd = Number(value.slice(4, 6))
  return mm >= 1 && mm <= 12 && dd >= 0 && dd <= 31
}

// ── Phase-4 key grammar table ───────────────────────────────────────────────

/** One primary-key grammar row. */
interface KeyGrammar {
  ai: string
  name: string
  /** Base grain; a GRAI/GDTI with a serial upgrades to `serialGrain`. */
  grain: Grain
  /**
   * How the primary value is shaped:
   *   'numeric-fixed'         all-digits, exactly `len`, with a mod-10 check.
   *   'cset82'                1..`max` CSET-82 chars, NO check digit.
   *   'numeric-core+serial'   `coreLen` all-digit core (mod-10 check) + optional
   *                           trailing serial (CSET-82, ≤`serialMax`).
   */
  kind: 'numeric-fixed' | 'cset82' | 'numeric-core+serial'
  len?: number
  max?: number
  coreLen?: number
  serialMax?: number
  serialGrain?: Grain
  /** Whether the numeric core carries a mod-10 check digit to verify. */
  checkDigit: boolean
}

/**
 * The defensible Phase-4 primary-key set. 01 GTIN keeps its dedicated
 * `parseDlPath`/route; the rows below are the additive keys `parseDlKey` serves.
 */
export const KEY_GRAMMAR: Readonly<Record<string, KeyGrammar>> = Object.freeze({
  '00': { ai: '00', name: 'SSCC', grain: 'instance', kind: 'numeric-fixed', len: 18, checkDigit: true },
  '414': { ai: '414', name: 'GLN', grain: 'place', kind: 'numeric-fixed', len: 13, checkDigit: true },
  // GIAI carries NO check digit — a real grain fact (GenSpecs), not a narrowing.
  '8004': { ai: '8004', name: 'GIAI', grain: 'asset', kind: 'cset82', max: 30, checkDigit: false },
  // GRAI: leading '0' + 13-digit core (14 total, mod-10) + optional serial ≤16.
  '8003': {
    ai: '8003', name: 'GRAI', grain: 'asset', kind: 'numeric-core+serial',
    coreLen: 14, serialMax: 16, serialGrain: 'instance', checkDigit: true,
  },
  // GDTI: 13-digit core (mod-10) + optional serial ≤17.
  '253': {
    ai: '253', name: 'GDTI', grain: 'document', kind: 'numeric-core+serial',
    coreLen: 13, serialMax: 17, serialGrain: 'instance', checkDigit: true,
  },
})

/** The primary keys `parseDlKey` accepts, plus 01 (served by the dedicated path). */
export const SUPPORTED_PRIMARY_KEYS = Object.freeze(['01', '00', '414', '8004', '8003', '253'])

/**
 * The generalised parse of a DL path over the Phase-4 key grammar table.
 * `segs` starts at the primary-key AI, e.g. ['8003','0...serial'] or
 * ['00','106141411234567891']. 01 is routed through `parseDlPath` instead.
 *
 * Returns the parsed key or a typed CONFORMANCE error. Does NOT run the mod-10
 * check (the route runs it so it can emit CHECKSUM_FAIL distinctly); it DOES
 * report the numeric core to check via `numericCore` and whether a check applies
 * via `checkDigit`.
 */
export interface DlKey {
  keyAi: string
  name: string
  grain: Grain
  /** The full primary value as it appeared (core + serial for GRAI/GDTI). */
  primaryValue: string
  /** The numeric string the route runs mod-10 over (undefined for check-less keys). */
  numericCore?: string
  checkDigit: boolean
  /** Ordered recognised qualifiers (stage-4: 10 lot, 21 serial for future 01 use). */
  qualifiers: Array<{ ai: string; value: string }>
  serial?: string
  lot?: string
  toleratedExtra: boolean
}

export type DlKeyError = { error: 'CONFORMANCE'; message: string; hint: string }

export function parseDlKey(segs: string[]): DlKey | DlKeyError {
  if (segs.length < 2) {
    return {
      error: 'CONFORMANCE',
      message: `expected a Digital Link primary key /{ai}/{value}; got /${segs.join('/')}`,
      hint: `stage-4 keys: ${SUPPORTED_PRIMARY_KEYS.join(', ')}`,
    }
  }
  const [ai, value] = segs
  const g = KEY_GRAMMAR[ai]
  if (!g) {
    return {
      error: 'CONFORMANCE',
      message: `unsupported primary key AI "${ai}"`,
      hint: `parseDlKey serves ${Object.keys(KEY_GRAMMAR).join(', ')}; /01 uses the GTIN path`,
    }
  }

  let grain: Grain = g.grain
  let serial: string | undefined
  let numericCore: string | undefined

  if (g.kind === 'numeric-fixed') {
    if (!isNumericLen(value, g.len!)) {
      return {
        error: 'CONFORMANCE',
        message: `${g.name} value "${value}" is not ${g.len} digits`,
        hint: `${g.name} (AI ${ai}) is exactly ${g.len} all-numeric digits`,
      }
    }
    numericCore = value
  } else if (g.kind === 'cset82') {
    if (!isCset82(value, 1, g.max!)) {
      return {
        error: 'CONFORMANCE',
        message: `${g.name} value "${value}" is not 1..${g.max} CSET-82 characters`,
        hint: `${g.name} (AI ${ai}) is CSET-82, max ${g.max}, and carries no check digit`,
      }
    }
    // no numericCore — GIAI has no check digit.
  } else {
    // numeric-core + optional serial (GRAI/GDTI)
    const core = value.slice(0, g.coreLen!)
    const rest = value.slice(g.coreLen!)
    if (!isNumericLen(core, g.coreLen!)) {
      return {
        error: 'CONFORMANCE',
        message: `${g.name} numeric core "${core}" is not ${g.coreLen} digits`,
        hint: `${g.name} (AI ${ai}) is a ${g.coreLen}-digit numeric core, optionally followed by a serial`,
      }
    }
    numericCore = core
    if (rest.length > 0) {
      if (!isCset82(rest, 1, g.serialMax!)) {
        return {
          error: 'CONFORMANCE',
          message: `${g.name} serial "${rest}" is not 1..${g.serialMax} CSET-82 characters`,
          hint: `${g.name} serial is CSET-82, max ${g.serialMax}`,
        }
      }
      serial = rest
      grain = g.serialGrain!
    }
  }

  // Walk any trailing AI/value pairs. Stage-4 recognises no path qualifiers for
  // these keys (their serial is carried IN the primary value, GS1 DL syntax);
  // anything trailing is tolerated-not-rejected (grain unchanged).
  const rest = segs.slice(2)
  let toleratedExtra = false
  if (rest.length % 2 !== 0) {
    return {
      error: 'CONFORMANCE',
      message: `dangling Digital Link segment after /${ai}/${value}: /${rest.join('/')}`,
      hint: 'Digital Link path AIs ride as /{ai}/{value} pairs',
    }
  }
  if (rest.length > 0) toleratedExtra = true

  return {
    keyAi: ai,
    name: g.name,
    grain,
    primaryValue: value,
    numericCore,
    checkDigit: g.checkDigit,
    qualifiers: [],
    serial,
    toleratedExtra,
  }
}
