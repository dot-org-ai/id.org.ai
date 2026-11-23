/** The six agent emails (14a–14c, 23a–23c; docs/agent-setup/HANDOFF.md section 6). */
import { describe, expect, it } from 'vitest'
import { setupEmailProps as P } from '../gallery/fixtures/setup-emails'
import { bankEmail, liveEmail, needsYouEmail, renderAgentEmail, renewalFailedEmail, stalledEmail, usageAlertEmail } from './AgentEmails'
import type { EmailParts } from './layout'

const all: [string, EmailParts][] = [
  ['14a', needsYouEmail(P.needsYou)],
  ['14b', stalledEmail(P.stalled)],
  ['14c', liveEmail(P.live)],
  ['23a', bankEmail(P.bank)],
  ['23b', renewalFailedEmail(P.payFailed)],
  ['23c', usageAlertEmail(P.usage)],
]

describe('agent emails', () => {
  it('there are six, with the subjects drawn', () => {
    expect(all.map(([, e]) => e.subject)).toEqual([
      'Claude Code needs your OK to go live',
      'Auto.dev setup has stopped',
      'Auto.dev is live · Growth, $299 a month',
      'Your bank needs to confirm $299 to Auto.dev',
      'The Auto.dev renewal didn’t go through',
      'Auto.dev data fees passed $500 this month',
    ])
  })
  it('each comes from agents@id.org.ai, has a plain-text part, and says why it was sent', () => {
    const reasons = [
      'an agent you approved is waiting on you',
      'a setup you approved has stopped',
      'an agent you approved spent money',
      'an agent you approved tried to spend',
      'an agent you approved spends on this card',
      'spend alerts are on for Auto.dev',
    ]
    all.forEach(([id, e], i) => {
      expect(e.from, id).toEqual({ name: 'id.org.ai', email: 'agents@id.org.ai' })
      const footer = `id.org.ai · Identity for people and agents · You’re getting this because ${reasons[i]}.`
      const m = renderAgentEmail(e, { fontBase: '' })
      expect(m.html, id).toContain(footer)
      expect(m.text.endsWith(`-- \n${footer}\n`), id).toBe(true)
    })
  })
  it('each has exactly one button, an absolute link, repeated in the text part', () => {
    for (const [id, e] of all) {
      const m = renderAgentEmail(e, { fontBase: '' })
      const hrefs = [...m.html.matchAll(/<a\b[^>]*href="([^"]+)"/g)].map((x) => x[1]!)
      expect(hrefs, id).toHaveLength(1)
      expect(hrefs[0], id).toMatch(/^https:\/\//)
      expect(m.text, id).toContain(hrefs[0]!)
    }
  })
  it('refuses a button link that is not http(s)', () => {
    expect(() => needsYouEmail({ ...P.needsYou, setupUrl: 'javascript:alert(1)' })).toThrow()
  })
  it('never carries a key: only its last four characters', () => {
    const m = renderAgentEmail(liveEmail({ ...P.live, keyLast4: 'sk_live_9f8e7d6c5b4a4f2a' }), { fontBase: '' })
    expect(m.html).toContain('Ends in 4f2a')
    expect(m.html + m.text).not.toContain('sk_live')
  })
  it('keeps request data on one line (no header or text injection through a name)', () => {
    const e = needsYouEmail({ ...P.needsYou, agent: 'Claude Code\r\nBcc: evil@example.com' })
    expect(e.subject).not.toMatch(/[\r\n]/)
    expect(e.text).not.toContain('\nBcc:')
  })
  it('14b gives the person the same line to paste that the setup page shows', () => {
    const m = renderAgentEmail(stalledEmail(P.stalled), { fontBase: '' })
    expect(m.html).toContain('Paste this to Claude Code')
    expect(m.text).toContain('Continue the Auto.dev setup. Read apis.ax/setup/su_8f2k and do what “next” says.')
  })
  it('23c: an alert never claims anything was stopped, with or without a limit', () => {
    expect(usageAlertEmail(P.usage).text).toContain('Claude Code has no spend limit on Auto.dev, so nothing was stopped. This is the alert at $500.')
    const limited = usageAlertEmail({ ...P.usage, spendLimit: '$1,000 a month' })
    expect(limited.text).toContain('Nothing was stopped')
    expect(limited.text).toContain('Change the limit:')
  })
  it('writes money as "$299 a month", never "/mo"', () => {
    for (const [id, e] of all) expect(e.text, id).not.toMatch(/\/mo\b/)
  })
})
