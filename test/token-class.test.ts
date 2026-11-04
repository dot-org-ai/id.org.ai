/**
 * The session class after H2 + H4: a sign-in session JWT carries either the
 * session audience (H4) or no `aud` at all (minted before H4). Any other
 * audience is an id_token, and never the Person's own credential (H2).
 */
import { describe, it, expect } from 'vitest'
import { idOrgAiTokenClass, isSessionAudience, ID_ORG_AI_SESSION_AUDIENCE } from '../src/sdk/auth/token-class'
import { SESSION_AUDIENCE, isSessionPayload } from '../worker/utils/session'
import { isSessionCookieJwt } from '../worker/utils/browser-session'

const JWT = { typ: 'JWT' }

describe('idOrgAiTokenClass', () => {
  it('the worker mints the audience the classifier accepts', () => {
    expect(SESSION_AUDIENCE).toBe(ID_ORG_AI_SESSION_AUDIENCE)
  })

  it('a session with the session audience (the string we sign) is a session', () => {
    expect(idOrgAiTokenClass(JWT, { aud: ID_ORG_AI_SESSION_AUDIENCE })).toBe('session')
  })

  it('aud null, or the session audience wrapped in an array, is not a session (we never sign either)', () => {
    expect(idOrgAiTokenClass(JWT, { aud: null })).toBe('id_token')
    expect(idOrgAiTokenClass(JWT, { aud: [ID_ORG_AI_SESSION_AUDIENCE] })).toBe('id_token')
  })

  it('a pre-H4 session with no aud is still a session', () => {
    expect(idOrgAiTokenClass(JWT, {})).toBe('session')
  })

  it('any other audience is an id_token, even alongside the session audience', () => {
    expect(idOrgAiTokenClass(JWT, { aud: 'cid_attacker' })).toBe('id_token')
    expect(idOrgAiTokenClass(JWT, { aud: [ID_ORG_AI_SESSION_AUDIENCE, 'cid_attacker'] })).toBe('id_token')
    expect(idOrgAiTokenClass(JWT, { aud: [] })).toBe('id_token')
    expect(idOrgAiTokenClass(JWT, { aud: '' })).toBe('id_token')
  })

  it('the session audience does not make an access token or a crit token a session', () => {
    expect(idOrgAiTokenClass({ typ: 'at+jwt' }, { aud: ID_ORG_AI_SESSION_AUDIENCE })).toBe('access_token')
    expect(idOrgAiTokenClass({ typ: 'JWT', crit: ['aud_bound'] }, { aud: ID_ORG_AI_SESSION_AUDIENCE })).toBe('other')
  })
})

/**
 * Review of PR #48, non-blocking 1: four copies of the session-audience rule
 * disagreed on `aud: null`. They now all call `isSessionAudience`; this pins
 * that they agree on every shape.
 */
describe('isSessionAudience is the one session-audience rule', () => {
  const b64url = (o: unknown) => btoa(JSON.stringify(o)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
  const cookieJwt = (payload: Record<string, unknown>) => `${b64url({ alg: 'RS256', typ: 'JWT' })}.${b64url(payload)}.sig`

  const cases: Array<[string, Record<string, unknown>, boolean]> = [
    ['absent', {}, true],
    ['the session audience', { aud: ID_ORG_AI_SESSION_AUDIENCE }, true],
    ['null', { aud: null }, false],
    ['an empty string', { aud: '' }, false],
    ['an empty array', { aud: [] }, false],
    ['[session]', { aud: [ID_ORG_AI_SESSION_AUDIENCE] }, false],
    ['[session, client]', { aud: [ID_ORG_AI_SESSION_AUDIENCE, 'cid_x'] }, false],
    ['a client id', { aud: 'cid_x' }, false],
    ['the legacy headless.ly', { aud: 'headless.ly' }, false],
    ['upper case', { aud: ID_ORG_AI_SESSION_AUDIENCE.toUpperCase() }, false],
    ['trailing space', { aud: `${ID_ORG_AI_SESSION_AUDIENCE} ` }, false],
  ]

  it.each(cases)('aud %s: every check agrees', (_label, payload, expected) => {
    expect(isSessionAudience(payload.aud)).toBe(expected)
    expect(idOrgAiTokenClass(JWT, payload) === 'session').toBe(expected)
    expect(isSessionPayload(payload)).toBe(expected)
    expect(isSessionCookieJwt(cookieJwt(payload))).toBe(expected)
  })
})
