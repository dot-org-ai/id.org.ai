/**
 * The blocks the agent setup cards are made of (docs/agent-setup). A screen's
 * fixture lists its blocks as plain data; each maps to one existing or new
 * component, so no screen carries layout of its own.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import { AGENT_ROUTES } from '../../agent-setup/routes'
import { rich, type Rich } from '../../agent-setup/rich'
import {
  Actions,
  Amount,
  Bar,
  Button,
  Checkbox,
  Dotted,
  Excerpt,
  Field,
  FootNote,
  FootText,
  KeyValue,
  Link,
  PayLine,
  PermissionList,
  PromptWell,
  QuoteWell,
  RadioCard,
  RadioGroup,
  Select,
  Spend,
  TermsAgree,
  Textarea,
  ToggleRow,
  Well,
  Who,
  type KV,
  type PermissionItem,
  type SelectOption,
  type SpendProps,
  type TermsAgreeProps,
} from '../../components'
import type { IconName } from '../../icons'

export type Block =
  | { kind: 'dotted' }
  /** The signed-in account, with Switch (→ 2a) unless `switchHref` is null. */
  | { kind: 'who'; name: string; sub: string; switchHref?: string | null }
  /** A well of key-value rows, with an optional group label above and an excerpt or link inside. */
  | { kind: 'well'; label?: string; items: KV[]; excerpt?: string; link?: { href: string; label: string }; tight?: boolean }
  /** A centred 13px line in the body (9e's pointer to the developer dashboard). */
  | { kind: 'line'; text: Rich }
  | { kind: 'select'; id: string; name: string; label: string; options: SelectOption[]; selected: string }
  | { kind: 'textarea'; id: string; name: string; label: string; placeholder?: string }
  | { kind: 'checkbox'; id: string; name: string; label: string; detail?: string; checked?: boolean }
  | { kind: 'toggle'; id: string; name: string; title: string; sub?: string; checked?: boolean }
  | { kind: 'radios'; legend: string; name: string; options: { value: string; title: string; description: string }[]; selected: string }
  | { kind: 'prompt'; label: string; text: string; copied?: boolean }
  | { kind: 'payline'; method?: string }
  | { kind: 'quote'; text: string }
  | { kind: 'permissions'; heading: string; items: PermissionItem[] }
  | { kind: 'spend'; spend: SpendProps }
  /** The month against a limit (19g): label and amount, the bar, then what made it up. */
  | { kind: 'limit'; label: string; amount: string; of: string; percent: number; lines: KV[] }

export function BlockView({ block: b }: { block: Block }): JSX.Element {
  switch (b.kind) {
    case 'dotted':
      return <Dotted />
    case 'who':
      return <Who name={b.name} sub={b.sub} right={b.switchHref === null ? undefined : <Link href={b.switchHref ?? AGENT_ROUTES.switchAccount}>Switch</Link>} />
    case 'well': {
      const well = (
        <Well variant={b.tight ? 'tight' : 'default'}>
          {b.items.map((i) => (
            <KeyValue {...i} />
          ))}
          {b.excerpt ? <Excerpt>{b.excerpt}</Excerpt> : null}
          {b.link ? <Link href={b.link.href}>{b.link.label}</Link> : null}
        </Well>
      )
      if (!b.label) return well
      return (
        <div class="id-stack id-stack--8">
          <div class="id-group-label">{b.label}</div>
          {well}
        </div>
      )
    }
    case 'line':
      return <FootText>{rich(b.text)}</FootText>
    case 'select':
      return (
        <Field id={b.id} label={b.label}>
          <Select id={b.id} name={b.name} options={b.options} selected={b.selected} />
        </Field>
      )
    case 'textarea':
      return (
        <Field id={b.id} label={b.label}>
          <Textarea id={b.id} name={b.name} placeholder={b.placeholder} maxlength={500} />
        </Field>
      )
    case 'checkbox':
      return (
        <Checkbox id={b.id} name={b.name} checked={b.checked} detail={b.detail}>
          {b.label}
        </Checkbox>
      )
    case 'toggle':
      return <ToggleRow id={b.id} name={b.name} checked={b.checked} title={b.title} sub={b.sub} />
    case 'radios':
      return (
        <RadioGroup legend={b.legend} layout="stack">
          {b.options.map((o) => (
            <RadioCard id={`${b.name}-${o.value}`} name={b.name} value={o.value} checked={o.value === b.selected} title={o.title} description={o.description} />
          ))}
        </RadioGroup>
      )
    case 'prompt':
      return <PromptWell label={b.label} text={b.text} copied={b.copied} />
    case 'payline':
      return <PayLine method={b.method} href={AGENT_ROUTES.paymentMethods} addHref={AGENT_ROUTES.paymentMethodNew} />
    case 'quote':
      return <QuoteWell>{b.text}</QuoteWell>
    case 'permissions':
      return <PermissionList heading={b.heading} items={b.items} />
    case 'spend':
      return <Spend {...b.spend} />
    case 'limit':
      return (
        <Well>
          <div class="id-limit__top">
            <span class="id-limit__label">{b.label}</span>
            <Amount amount={b.amount} of={b.of} />
          </div>
          <Bar percent={b.percent} full={b.percent >= 100} />
          <div class="id-limit__lines">
            {b.lines.map((l) => (
              <KeyValue {...l} />
            ))}
          </div>
        </Well>
      )
  }
}

export function Blocks({ blocks }: { blocks: Block[] }): JSX.Element {
  return (
    <>
      {blocks.map((b) => (
        <BlockView block={b} />
      ))}
    </>
  )
}

export interface ActionSpec {
  label: string
  /** A link (navigation). Otherwise a submit button posting `decision=<value>`. */
  href?: string
  value?: string
  icon?: IconName
  /** Open in a new tab, so this page can still finish (the developer dashboard). */
  newTab?: boolean
  busyLabel?: string
  /** The label follows a control: its name and a template with `{label}`. */
  follows?: { control: string; template: string }
}

export interface FootProps {
  terms?: TermsAgreeProps
  secondary?: ActionSpec
  primary?: ActionSpec
  /** The centred line under the actions. */
  note?: Rich
  /** A 14px icon before the note (13a's "Admins get an email"). */
  noteIcon?: IconName
}

function ActionButton({ a, variant, needsTerms }: { a: ActionSpec; variant: 'primary' | 'secondary'; needsTerms?: boolean }): JSX.Element {
  return (
    <Button variant={variant} block href={a.href} newTab={a.newTab} name={a.href === undefined ? 'decision' : undefined} value={a.value} icon={a.icon} busyLabel={a.busyLabel} follows={a.follows} needsTerms={needsTerms}>
      {a.label}
    </Button>
  )
}

/** The action band's content: the terms line, the two actions (secondary left, primary right), then one note. */
export function Foot({ terms, secondary, primary, note, noteIcon }: FootProps): JSX.Element {
  const both = secondary && primary
  return (
    <>
      {terms ? <TermsAgree {...terms} /> : null}
      {both ? (
        <Actions>
          <ActionButton a={secondary} variant="secondary" />
          <ActionButton a={primary} variant="primary" needsTerms={Boolean(terms)} />
        </Actions>
      ) : primary ? (
        <ActionButton a={primary} variant="primary" needsTerms={Boolean(terms)} />
      ) : secondary ? (
        <ActionButton a={secondary} variant="secondary" />
      ) : null}
      {note ? noteIcon ? <FootNote icon={noteIcon}>{rich(note)}</FootNote> : <FootText>{rich(note)}</FootText> : null}
    </>
  )
}

/** Whether a foot posts anything (then the card is a form). */
export function footPosts(f: FootProps): boolean {
  return [f.primary, f.secondary].some((a) => a && a.href === undefined)
}
