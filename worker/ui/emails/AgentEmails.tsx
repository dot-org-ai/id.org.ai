/**
 * The six agent emails, and only these (docs/agent-setup/HANDOFF.md section 6):
 * the person is needed (14a), the setup stalled (14b), money moved (14c), the
 * bank needs the person (23a), a renewal failed (23b), usage passed an alert
 * mark (23c). Each button deep-links to the screen that resolves it.
 *
 * They share one shape on the existing light template: a heading, one
 * paragraph, a box of facts (or a line to paste), one button, one closing
 * line, and a footer that says why the person is getting it.
 */
import {
  AGENTS_SENDER,
  EmailButton,
  EmailContent,
  emailFooter,
  EmailHeading,
  EmailKeyValues,
  EmailParagraph,
  EmailPrompt,
  emailText,
  httpUrl,
  oneLine,
  renderEmail,
  type EmailParts,
  type EmailRenderOptions,
  type RenderedEmail,
} from './layout'

interface AgentEmail {
  subject: string
  heading: string
  body: string
  rows?: [string, string][]
  prompt?: { label: string; text: string }
  button: { label: string; url: string }
  closing: string
  /** "an agent you approved is waiting on you": completes "You’re getting this because …". */
  reason: string
}

function agentEmail(e: AgentEmail): EmailParts {
  const url = httpUrl(e.button.url)
  const rows = (e.rows ?? []).map(([k, v]): [string, string] => [k, oneLine(v)])
  const footer = emailFooter(e.reason)
  const box = e.prompt ? <EmailPrompt label={e.prompt.label} text={oneLine(e.prompt.text)} /> : <EmailKeyValues rows={rows} />
  const boxText = e.prompt ? `${e.prompt.label}:\n${oneLine(e.prompt.text)}` : rows.map(([k, v]) => `${k}: ${v}`).join('\n')
  return {
    from: { name: 'id.org.ai', email: AGENTS_SENDER },
    subject: oneLine(e.subject),
    content: (
      <EmailContent
        footer={footer}
        blocks={[<EmailHeading>{e.heading}</EmailHeading>, <EmailParagraph>{e.body}</EmailParagraph>, box, <EmailButton href={url}>{e.button.label}</EmailButton>, <EmailParagraph>{e.closing}</EmailParagraph>]}
      />
    ),
    text: emailText([e.heading, e.body, boxText, `${e.button.label}: ${url}`, e.closing], footer),
  }
}

// ── 14a · the agent needs you ────────────────────────────────────────────────

export interface NeedsYouEmailProps {
  /** "Claude Code" */
  agent: string
  /** "Auto.dev" */
  product: string
  /** "Growth · $299/month" */
  plan: string
  /** "Nov 22, 2:16 PM EST", in the person's time zone. */
  since: string
  /** The setup page, where the person approves (9c). */
  setupUrl: string
}

export function needsYouEmail(p: NeedsYouEmailProps): EmailParts {
  const agent = oneLine(p.agent)
  const product = oneLine(p.product)
  return agentEmail({
    subject: `${agent} needs your OK to go live`,
    heading: `${agent} needs your OK`,
    body: `It made a real call to ${product} with the test key. A live key needs a spend limit from you.`,
    rows: [
      ['Agent', agent],
      ['Setting up', product],
      ['Plan', p.plan],
      ['Waiting since', p.since],
    ],
    button: { label: 'Review and approve', url: p.setupUrl },
    closing: 'The test key keeps working until you decide.',
    reason: 'an agent you approved is waiting on you',
  })
}

// ── 14b · the setup stalled ──────────────────────────────────────────────────

export interface StalledEmailProps {
  agent: string
  product: string
  /** "the first call": where it stopped. */
  stoppedAt: string
  /** "10 minutes" */
  quietFor: string
  /** The line to paste to the agent (the same one 9d shows). */
  prompt: string
  setupUrl: string
}

export function stalledEmail(p: StalledEmailProps): EmailParts {
  const agent = oneLine(p.agent)
  const product = oneLine(p.product)
  return agentEmail({
    subject: `${product} setup has stopped`,
    heading: `Setup stopped at ${oneLine(p.stoppedAt)}`,
    body: `${agent} hasn’t called ${product} in ${oneLine(p.quietFor)}. It may have stopped or declared itself done.`,
    prompt: { label: `Paste this to ${agent}`, text: p.prompt },
    button: { label: 'Open setup', url: p.setupUrl },
    closing: 'Nothing is charged until a live key is issued.',
    reason: 'a setup you approved has stopped',
  })
}

// ── 14c · live, with the receipt ─────────────────────────────────────────────

export interface LiveEmailProps {
  agent: string
  product: string
  workspace: string
  /** "Growth" and "$299/month". */
  planName: string
  planPrice: string
  /** "$500/month" */
  spendLimit: string
  /** The live key's last four characters. Never the key. */
  keyLast4: string
  /** "3 min 12 s" */
  took: string
  /** "Nov 22, 2:17 PM EST" */
  when: string
  /** The product's developer dashboard. */
  dashboardUrl: string
}

export function liveEmail(p: LiveEmailProps): EmailParts {
  const product = oneLine(p.product)
  const plan = `${oneLine(p.planName)} · ${oneLine(p.planPrice)}`
  return agentEmail({
    subject: `${product} is live · ${oneLine(p.planName)}, ${oneLine(p.planPrice)}`,
    heading: `${product} is live`,
    body: `${oneLine(p.agent)} finished setup in ${oneLine(p.took)} and subscribed for ${oneLine(p.workspace)}.`,
    rows: [
      ['Workspace', p.workspace],
      ['Plan', plan],
      ['Spend limit', p.spendLimit],
      ['Live key', `Ends in ${p.keyLast4.slice(-4)}`],
      ['When', p.when],
    ],
    button: { label: 'Open developer dashboard', url: p.dashboardUrl },
    closing: 'Usage, logs and keys are there. Wasn’t you? Remove the agent on id.org.ai and its keys stop working right away.',
    reason: 'an agent you approved spent money',
  })
}

// ── 23a · the bank needs to confirm ──────────────────────────────────────────

export interface BankEmailProps {
  agent: string
  product: string
  planName: string
  /** "$299.00" and, for the subject, "$299". */
  amount: string
  amountShort: string
  /** "Visa ending 4417" */
  card: string
  /** The setup page, where the person confirms (19e). */
  confirmUrl: string
}

export function bankEmail(p: BankEmailProps): EmailParts {
  const agent = oneLine(p.agent)
  const product = oneLine(p.product)
  const plan = oneLine(p.planName)
  return agentEmail({
    subject: `Your bank needs to confirm ${oneLine(p.amountShort)} to ${product}`,
    heading: 'Your bank needs to hear from you',
    body: `${agent} tried to start ${plan} on ${product}. Your bank wants you to confirm the payment first.`,
    rows: [
      ['Agent', agent],
      ['For', `${product} · ${plan}`],
      ['Amount', p.amount],
      ['Card', p.card],
    ],
    button: { label: 'Confirm payment', url: p.confirmUrl },
    closing: 'Nothing is charged until you confirm. The test key keeps working.',
    reason: 'an agent you approved tried to spend',
  })
}

// ── 23b · a renewal failed ───────────────────────────────────────────────────

export interface RenewalFailedEmailProps {
  agent: string
  product: string
  workspace: string
  /** "4417" */
  cardLast4: string
  /** "$425.00" */
  invoice: string
  /** "Dec 22", "Dec 25", "Dec 29". */
  firstTry: string
  nextTry: string
  keyStops: string
  /** The screen that resolves it (19f). */
  updateUrl: string
}

export function renewalFailedEmail(p: RenewalFailedEmailProps): EmailParts {
  const stops = oneLine(p.keyStops)
  const next = oneLine(p.nextTry)
  return agentEmail({
    subject: `The ${oneLine(p.product)} renewal didn’t go through`,
    heading: 'A renewal didn’t go through',
    body: `${oneLine(p.workspace)}’s card ending ${p.cardLast4.slice(-4)} was declined. The next try is ${next}.`,
    rows: [
      ['Invoice', p.invoice],
      ['First try', `${oneLine(p.firstTry)} · declined`],
      ['Second try', next],
      ['Live key stops', stops],
    ],
    button: { label: 'Update payment method', url: p.updateUrl },
    closing: `${oneLine(p.agent)} keeps working until ${stops}.`,
    reason: 'an agent you approved spends on this card',
  })
}

// ── 23c · usage passed an alert mark ─────────────────────────────────────────

export interface UsageAlertEmailProps {
  agent: string
  product: string
  /** "$500": the mark the month's usage passed. */
  mark: string
  /** "Growth · $299.00" */
  plan: string
  /** "$500.60 · 200,240 calls" */
  feesSoFar: string
  /** "$1,000", or none when this was the last mark. */
  nextMark?: string
  /** "None", or "$1,000/month". */
  spendLimit: string
  /** Where the person sets a limit. */
  limitUrl: string
}

export function usageAlertEmail(p: UsageAlertEmailProps): EmailParts {
  const product = oneLine(p.product)
  const mark = oneLine(p.mark)
  const noLimit = oneLine(p.spendLimit) === 'None'
  const rows: [string, string][] = [
    ['Plan', p.plan],
    ['Data fees so far', p.feesSoFar],
  ]
  if (p.nextMark) rows.push(['Next alert', p.nextMark])
  rows.push(['Spend limit', p.spendLimit])
  return agentEmail({
    subject: `${product} data fees passed ${mark} this month`,
    heading: `Data fees passed ${mark}`,
    // An alert never stops anything; say so, and why (no limit, or one not reached).
    body: noLimit ? `${oneLine(p.agent)} has no spend limit on ${product}, so nothing was stopped. This is the alert at ${mark}.` : `Nothing was stopped: ${oneLine(p.agent)} is still inside its ${oneLine(p.spendLimit)} limit on ${product}. This is the alert at ${mark}.`,
    rows,
    button: { label: noLimit ? 'Set a limit' : 'Change the limit', url: p.limitUrl },
    closing: `Turn alerts off in the ${product} developer dashboard.`,
    reason: `spend alerts are on for ${product}`,
  })
}

export const renderAgentEmail = (parts: EmailParts, opts?: EmailRenderOptions): RenderedEmail => renderEmail(parts, opts)
