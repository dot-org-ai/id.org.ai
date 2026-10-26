/**
 * The session class after H2 + H4: a sign-in session JWT carries either the
 * session audience (H4) or no `aud` at all (minted before H4). Any other
 * audience is an id_token, and never the Person's own credential (H2).
 */
import { describe, it, expect } from 'vitest'
import { idOrgAiTokenClass, ID_ORG_AI_SESSION_AUDIENCE } from '../src/sdk/auth/token-class'
import { SESSION_AUDIENCE } from '../worker/utils/session'

const JWT = { typ: 'JWT' }

describe('idOrgAiTokenClass', () => {
  it('the worker mints the audience the classifier accepts', () => {
    expect(SESSION_AUDIENCE).toBe(ID_ORG_AI_SESSION_AUDIENCE)
  })

  it('a session with the session audience, alone, is a session', () => {
    expect(idOrgAiTokenClass(JWT, { aud: ID_ORG_AI_SESSION_AUDIENCE })).toBe('session')
    expect(idOrgAiTokenClass(JWT, { aud: [ID_ORG_AI_SESSION_AUDIENCE] })).toBe('session')
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
