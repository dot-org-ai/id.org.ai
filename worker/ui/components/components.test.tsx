/**
 * Markup contracts for the design system (prompts/02-design-system.md, Task 2):
 * roles, labels, aria-*, button types, and never an inline style.
 */
import { readdirSync, readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { renderHtml } from '../render'
import { ComponentSheet } from '../gallery/components-sheet'
import {
  AccountRow,
  Actions,
  AnotherAccountRow,
  AppTile,
  Avatar,
  Button,
  Card,
  CardHead,
  Checkbox,
  CodeInput,
  Connector,
  CopyButton,
  Dotted,
  Em,
  Field,
  Input,
  PermissionList,
  RadioCard,
  RadioGroup,
  Select,
  SourceRow,
  StatusList,
  Who,
  initials,
} from '.'

async function dom(el: JSX.Element): Promise<Document> {
  const html = await renderHtml(el, { title: 't' })
  return new DOMParser().parseFromString(html, 'text/html')
}

describe('every component', () => {
  it('renders without inline styles or inline scripts (the full component sheet)', async () => {
    const html = await renderHtml(<ComponentSheet />, { title: 't' })
    expect(html).not.toMatch(/\sstyle=/i)
    expect(html).not.toMatch(/<style[\s>]/i)
    expect(html).not.toMatch(/\son[a-z]+=/i)
    for (const tag of html.match(/<script\b[^>]*>/gi) ?? []) expect(tag).toMatch(/\ssrc="/)
  })

  it('component files contain no colour literals (everything comes from tokens)', () => {
    for (const f of readdirSync('worker/ui/components')) {
      if (f === 'ProviderMark.tsx') continue // third-party brand artwork, checked below
      const src = readFileSync(`worker/ui/components/${f}`, 'utf8')
      expect(src, f).not.toMatch(/oklch\(|rgba?\(|#[0-9a-f]{6}\b/i)
    }
  })

  it('ProviderMark’s only colour literals are Google’s and Microsoft’s brand colours', () => {
    const src = readFileSync('worker/ui/components/ProviderMark.tsx', 'utf8')
    expect(src).not.toMatch(/oklch\(|rgba?\(/i)
    // Written without '#' so this file passes the guard above.
    const hexes = [...new Set((src.match(/#[0-9a-f]{6}\b/gi) ?? []).map((h) => h.slice(1).toUpperCase()))].sort()
    expect(hexes).toEqual(['00A4EF', '34A853', '4285F4', '7FBA00', 'EA4335', 'F25022', 'FBBC05', 'FFB900'])
  })
})

describe('Button', () => {
  it('is a submit button by default, a plain button on request, and a link with href', async () => {
    const d = await dom(
      <>
        <Button variant="primary">Allow</Button>
        <Button variant="secondary" type="button">Cancel</Button>
        <Button variant="secondary" href="/login">Sign in another way</Button>
      </>,
    )
    const [allow, cancel] = Array.from(d.querySelectorAll('button'))
    expect(allow!.getAttribute('type')).toBe('submit')
    expect(cancel!.getAttribute('type')).toBe('button')
    expect(d.querySelector('a.id-btn')!.getAttribute('href')).toBe('/login')
    expect(d.querySelectorAll('div.id-btn').length).toBe(0)
  })

  it('busy: disabled, aria-busy and the progressive label', async () => {
    const d = await dom(
      <Button variant="primary" busy busyLabel="Confirming…">
        Confirm
      </Button>,
    )
    const b = d.querySelector('button')!
    expect(b.hasAttribute('disabled')).toBe(true)
    expect(b.getAttribute('aria-busy')).toBe('true')
    expect(b.textContent).toBe('Confirming…')
  })
})

describe('Field, Select, CodeInput', () => {
  it('styles the open list only where the browser supports it, with no motion under reduced motion', () => {
    const css = readFileSync('worker/ui/ui.css', 'utf8')
    const start = css.indexOf('@supports (appearance: base-select)')
    expect(start).toBeGreaterThan(-1)
    // Every base-select rule sits inside the @supports block, so other browsers keep the native list.
    const outside = css.slice(0, start).match(/appearance:\s*base-select/g) ?? []
    expect(outside).toEqual([])
    const block = css.slice(start)
    expect(block).toMatch(/\.id-select::picker-icon\s*{\s*display:\s*none;/)
    expect(block).toMatch(/@media \(prefers-reduced-motion: reduce\)\s*{\s*\.id-select::picker\(select\)\s*{\s*transition:\s*none;/)
  })

  it('labels its control and links the hint or error', async () => {
    const d = await dom(
      <>
        <Field id="e" label="Email" hint="We'll send a code.">
          <Input id="e" name="email" type="email" hint />
        </Field>
        <Field id="w" label="Workspace" error="That name is taken.">
          <Input id="w" name="ws" error />
        </Field>
      </>,
    )
    expect(d.querySelector('label[for="e"]')!.textContent).toBe('Email')
    expect(d.getElementById('e')!.getAttribute('aria-describedby')).toBe('e-hint')
    expect(d.getElementById('w')!.getAttribute('aria-invalid')).toBe('true')
    expect(d.getElementById('w')!.getAttribute('aria-describedby')).toBe('w-error')
  })

  it('Select keeps the selected option', async () => {
    const d = await dom(<Select id="s" name="org_id" options={[{ value: 'a', label: 'A' }, { value: 'b', label: 'B' }]} selected="b" />)
    expect(d.querySelector<HTMLSelectElement>('select')!.value).toBe('b')
  })

  it('CodeInput: a labelled group, one labelled box per character, one-time-code on the first', async () => {
    const d = await dom(<CodeInput length={6} value="48" label="Enter the 6-digit code" />)
    const group = d.querySelector('[role="group"]')!
    expect(group.getAttribute('aria-label')).toBe('Enter the 6-digit code')
    const boxes = Array.from(d.querySelectorAll('input'))
    expect(boxes).toHaveLength(6)
    expect(boxes[0]!.getAttribute('autocomplete')).toBe('one-time-code')
    expect(boxes[0]!.getAttribute('inputmode')).toBe('numeric')
    expect(boxes[5]!.getAttribute('aria-label')).toBe('Character 6 of 6')
    expect(boxes.map((b) => b.value).join('')).toBe('48')
    expect(boxes.every((b) => b.getAttribute('name') === 'code')).toBe(true)
  })

  it('CodeInput for devices: 8 boxes and the separator after the fourth', async () => {
    const d = await dom(<CodeInput length={8} value="WDJB-MJHT" label="Enter the code" />)
    const group = d.querySelector('[role="group"]')!
    expect(Array.from(group.children).map((c) => c.tagName)).toEqual(['INPUT', 'INPUT', 'INPUT', 'INPUT', 'SPAN', 'INPUT', 'INPUT', 'INPUT', 'INPUT'])
    expect(Array.from(d.querySelectorAll('input')).map((b) => b.value).join('')).toBe('WDJBMJHT')
  })
})

describe('RadioGroup, RadioCard, Checkbox', () => {
  it('groups radio cards in a fieldset with a legend; inputs stay real and focusable', async () => {
    const d = await dom(
      <RadioGroup legend="Access" layout="row">
        <RadioCard id="a" name="access" value="read" title="Read only" />
        <RadioCard id="b" name="access" value="act" checked accent title="Read and act" />
      </RadioGroup>,
    )
    expect(d.querySelector('fieldset > legend')!.textContent).toBe('Access')
    const radios = Array.from(d.querySelectorAll<HTMLInputElement>('input[type="radio"]'))
    expect(radios.map((r) => r.checked)).toEqual([false, true])
    expect(d.querySelector('label[for="b"] .id-accent-dot')).not.toBeNull()
  })

  it('Checkbox wraps a real checkbox', async () => {
    const d = await dom(
      <Checkbox id="r" name="remember" checked>
        Remember
      </Checkbox>,
    )
    expect(d.querySelector<HTMLInputElement>('input[type="checkbox"]#r')!.checked).toBe(true)
    expect(d.querySelector('label[for="r"]')!.textContent).toBe('Remember')
  })
})

describe('CopyButton', () => {
  it('is hidden until its script runs, named, with a status region', async () => {
    const d = await dom(<CopyButton value="x" />)
    const b = d.querySelector('button')!
    expect(b.hasAttribute('hidden')).toBe(true)
    expect(b.getAttribute('type')).toBe('button')
    expect(b.getAttribute('aria-label')).toBe('Copy')
    expect(b.nextElementSibling!.getAttribute('role')).toBe('status')
  })

  it('the labelled variant is named by its text', async () => {
    const d = await dom(<CopyButton value="x" labelled />)
    expect(d.querySelector('button')!.hasAttribute('aria-label')).toBe(false)
    expect(d.querySelector('button')!.textContent).toContain('Copy details')
  })
})

describe('Identity', () => {
  it('initials', () => {
    expect(initials('Bryant Skarda')).toBe('BS')
    expect(initials('Nathan Q Clevenger')).toBe('NC')
    expect(initials('Cher')).toBe('CH')
    expect(initials(undefined, 'pat@example.com')).toBe('P')
  })

  it('Avatar is decorative; a photo gets no-referrer and fixed size', async () => {
    const d = await dom(<Avatar name="B S" src="https://example.com/a.png" />)
    const img = d.querySelector('img')!
    expect(d.querySelector('.id-avatar')!.getAttribute('aria-hidden')).toBe('true')
    expect(img.getAttribute('referrerpolicy')).toBe('no-referrer')
    expect(img.getAttribute('width')).toBe('32')
    expect(img.getAttribute('alt')).toBe('')
  })

  it('Who shows the name and email; AccountRow posts the session or links', async () => {
    const d = await dom(
      <>
        <Who name="Bryant Skarda" sub="bryant@driv.ly" />
        <AccountRow name="Bryant Skarda" email="bryant@driv.ly" sessionValue="sid_1" lastUsedHere />
        <AnotherAccountRow href="/login?prompt=login">Use another account</AnotherAccountRow>
      </>,
    )
    expect(d.querySelector('.id-who')!.textContent).toContain('bryant@driv.ly')
    const row = d.querySelector('button.id-account')!
    expect(row.getAttribute('type')).toBe('submit')
    expect(row.getAttribute('name')).toBe('session')
    expect(row.getAttribute('value')).toBe('sid_1')
    expect(row.textContent).toContain('Last used here')
    expect(d.querySelector('a.id-account--another')!.getAttribute('href')).toBe('/login?prompt=login')
  })

  it('AppTile: logos are <img> with no-referrer, fixed size and empty alt, plus the monogram fallback hook', async () => {
    const d = await dom(<AppTile content={{ kind: 'logo', src: 'https://chatgpt.com/logo.png', monogram: 'Cx' }} />)
    const img = d.querySelector('img')!
    expect(img.getAttribute('referrerpolicy')).toBe('no-referrer')
    expect(img.getAttribute('alt')).toBe('')
    expect(img.getAttribute('width')).toBe('32')
    expect(d.querySelector('[data-js="logo"]')!.getAttribute('data-monogram')).toBe('Cx')
  })
})

describe('Card, connector, lists', () => {
  it('one h1 per card head; names highlighted inside the description', async () => {
    const d = await dom(
      <Card>
        <CardHead
          title="Sign in"
          description={
            <>
              to continue to <Em>headless.ly</Em>
            </>
          }
        />
      </Card>,
    )
    expect(d.querySelectorAll('h1')).toHaveLength(1)
    expect(d.querySelector('.id-desc .id-em')!.textContent).toBe('headless.ly')
  })

  it('the connector is hidden from assistive tech and carries its state', async () => {
    const d = await dom(<Connector left={{ kind: 'org' }} right={{ kind: 'monogram', text: 'h' }} state="connecting" />)
    const c = d.querySelector('.id-conn')!
    expect(c.getAttribute('aria-hidden')).toBe('true')
    expect(c.getAttribute('data-state')).toBe('connecting')
  })

  it('two actions sit in the action band; Dotted is decorative', async () => {
    const d = await dom(
      <>
        <Actions>
          <Button variant="secondary">Cancel</Button>
          <Button variant="primary">Allow</Button>
        </Actions>
        <Dotted label="or" />
      </>,
    )
    expect(d.querySelectorAll('[data-actions] > button')).toHaveLength(2)
    expect(Array.from(d.querySelectorAll('.id-dots')).every((x) => x.getAttribute('aria-hidden') === 'true')).toBe(true)
  })

  it('permission rows are native details/summary; act rows carry the note', async () => {
    const d = await dom(
      <PermissionList
        heading="Codex would like to"
        items={[
          { icon: 'search', title: 'Read', detail: 'd', scope: 'sb:read' },
          { icon: 'pen', title: 'Act', detail: 'd', scope: 'sb:do', act: true, actNote: 'Changes are made in your name.' },
        ]}
      />,
    )
    expect(d.querySelectorAll('details > summary')).toHaveLength(2)
    expect(d.querySelectorAll('.id-perm__note')).toHaveLength(1)
  })

  it('escapes request data (scope strings, client names)', async () => {
    const d = await dom(<PermissionList heading="<b>x</b>" items={[{ icon: 'globe', title: '<script>alert(1)</script>', detail: 'd', scope: '<img src=x>' }]} />)
    expect(d.querySelector('script')).toBeNull()
    expect(d.querySelector('img')).toBeNull()
    expect(d.querySelector('.id-perm__title')!.textContent).toBe('<script>alert(1)</script>')
  })

  it('SourceRow: details with key/values and links, plus copy', async () => {
    const d = await dom(
      <SourceRow display="chatgpt.com/x.json" icon="globe" details={[{ k: 'Runs on', v: 'This computer' }]} links={[{ href: 'https://chatgpt.com/p', label: 'Privacy' }]} copyValue="https://chatgpt.com/x.json" />,
    )
    expect(d.querySelector('details summary')!.textContent).toContain('chatgpt.com/x.json')
    expect(d.querySelector('button[data-js="copy"]')!.getAttribute('data-value')).toBe('https://chatgpt.com/x.json')
  })

  it('the status list is a polite live region', async () => {
    const d = await dom(<StatusList items={[{ title: 'Waiting for a push', current: true }, { title: 'Claimed' }]} />)
    expect(d.querySelector('[aria-live="polite"]')).not.toBeNull()
    expect(d.querySelectorAll('.id-status--current')).toHaveLength(1)
  })
})
