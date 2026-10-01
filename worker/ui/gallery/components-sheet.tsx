/**
 * /__design/components: every component in spec/components.md, in every
 * variant, for review by eye. Dev only, frozen like the rest of the gallery.
 */
import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  AccountList,
  AccountRow,
  Actions,
  AnotherAccountRow,
  AppTile,
  Avatar,
  Button,
  Card,
  CardFoot,
  CardHead,
  Checkbox,
  CodeBlock,
  CodeInput,
  Connector,
  CopyButton,
  Countdown,
  DeviceCodeWell,
  Disclosure,
  Dotted,
  Em,
  Excerpt,
  Field,
  FootNote,
  FootText,
  IconTile,
  Input,
  KeyValue,
  KeyValues,
  Link,
  Meta,
  Note,
  Page,
  PermissionList,
  Pill,
  Pre,
  ResendTimer,
  ProviderButton,
  Providers,
  QuoteWell,
  RadioCard,
  RadioGroup,
  Select,
  SingleTile,
  SourceRow,
  Stack,
  Stats,
  StatusList,
  Step,
  Textarea,
  Well,
  WarningCallout,
  Who,
  WhoMeta,
  type ConnectorState,
} from '../components'
import { Icon, type IconName } from '../icons'

const ICONS: IconName[] = ['chev_r', 'chev_d', 'chev_ud', 'check', 'key', 'mail', 'copy', 'user', 'search', 'pen', 'laptop', 'terminal', 'shield', 'alert', 'clock', 'plus', 'globe', 'logout', 'lock', 'x', 'send', 'commit', 'building', 'bot', 'external']
const STATES: ConnectorState[] = ['idle', 'connecting', 'done', 'broken', 'ok', 'fail']

function Section({ title, children }: { title: string; children: Child }): JSX.Element {
  return (
    <section class="id-sheet__section">
      <h2 class="id-sheet__heading">{title}</h2>
      {children}
    </section>
  )
}

export function ComponentSheet(): JSX.Element {
  return (
    <Page>
      <Card foot={<CardFoot><FootText>Every variant of every component (spec/components.md).</FootText></CardFoot>}>
        <CardHead
          connector={<Connector left={{ kind: 'org' }} right={{ kind: 'monogram', text: 'Cx' }} />}
          title="Component sheet"
          description={
            <>
              The auth UI's building blocks, with <Em>tokens</Em> only.
            </>
          }
        />
        <div class="id-sheet">
          <Section title="Connector states">
            {STATES.map((s) => (
              <Stack gap={6}>
                <span class="id-label">{s}</span>
                <Connector left={{ kind: 'org' }} right={{ kind: 'icon', icon: 'terminal' }} state={s} />
              </Stack>
            ))}
          </Section>
          <Section title="App tiles">
            <div class="id-sheet__row">
              <AppTile content={{ kind: 'org' }} />
              <AppTile content={{ kind: 'monogram', text: 'h' }} />
              <AppTile content={{ kind: 'monogram', text: 'Cx' }} />
              <AppTile content={{ kind: 'monogram', text: '.d' }} />
              <AppTile content={{ kind: 'icon', icon: 'terminal' }} />
              <AppTile content={{ kind: 'icon', icon: 'bot' }} />
              <AppTile content={{ kind: 'logo', src: '/orgLogo.svg', monogram: 'id' }} />
              <AppTile content={{ kind: 'logo', src: 'https://example.invalid/logo.png', monogram: 'Cx' }} />
              <AppTile content={{ kind: 'logo', src: 'http://insecure.example/logo.png', monogram: 'h' }} />
              <IconTile icon="building" />
              <SingleTile content={{ kind: 'org' }} />
            </div>
          </Section>
          <Section title="Buttons">
            <div class="id-sheet__row">
              <Button variant="primary" type="button">Primary</Button>
              <Button variant="secondary" type="button">Secondary</Button>
              <Button variant="ghost" type="button">Ghost</Button>
              <Button variant="primary" type="button" icon="mail">With icon</Button>
              <Button variant="ghost" size="sm" type="button" icon="logout">Small ghost</Button>
              <Button variant="primary" size="sm" type="button">Small primary</Button>
              <Button variant="secondary" size="sm" type="button">Small secondary</Button>
              <Button variant="secondary" href="#" disabled>Disabled link</Button>
              <Button variant="primary" type="button" busy busyLabel="Confirming…">Confirm</Button>
              <Button variant="secondary" type="button" disabled>Disabled</Button>
              <Button variant="secondary" href="#">Link button</Button>
            </div>
            <Actions>
              <Button variant="secondary" block type="button">Cancel</Button>
              <Button variant="primary" block type="button">Allow</Button>
            </Actions>
          </Section>
          <Section title="Providers">
            <Providers>
              <ProviderButton provider="github" href="#" lastUsed />
              <ProviderButton provider="google" href="#" />
              <ProviderButton provider="microsoft" href="#" />
              <ProviderButton provider="apple" href="#" />
            </Providers>
          </Section>
          <Section title="Fields">
            <Field id="sheet-email" label="Email">
              <Input id="sheet-email" name="email" type="email" placeholder="you@company.com" />
            </Field>
            <Field id="sheet-name" label="Name" aside="From GitHub" hint="Shown to apps you sign in to.">
              <Input id="sheet-name" name="name" value="Bryant Skarda" hint />
            </Field>
            <Field id="sheet-err" label="Workspace" error="That name is taken.">
              <Input id="sheet-err" name="ws" value="Drivly" error />
            </Field>
            <Field id="sheet-select" label="Workspace">
              <Select id="sheet-select" name="org" options={[{ value: 'a', label: 'Drivly' }, { value: 'b', label: '.do Industries' }]} selected="a" />
            </Field>
            <Field id="sheet-note" label="Note">
              <Textarea id="sheet-note" name="note" placeholder="Why you need it (optional)" maxlength={500} />
            </Field>
          </Section>
          <Section title="Code input">
            <CodeInput length={6} value="4829" focusIndex={4} label="Enter the 6-digit code" />
            <CodeInput length={8} focusIndex={0} label="Enter the code from your terminal" />
          </Section>
          <Section title="Radio cards and checkbox">
            <RadioGroup legend="Access" layout="row">
              <RadioCard id="sheet-r1" name="sheet-access" value="read" title="Read only" description="Search and read your Startups" />
              <RadioCard id="sheet-r2" name="sheet-access" value="act" checked accent title="Read and act" description="Also run Verbs that change them" />
            </RadioGroup>
            <RadioGroup legend="Trust level" layout="stack">
              <RadioCard id="sheet-t1" name="sheet-trust" value="sandboxed" title="Sandboxed" description="Works on sandbox copies." />
              <RadioCard id="sheet-t2" name="sheet-trust" value="trusted" checked title="Trusted" description="Asks you before it sends, deletes or spends." />
            </RadioGroup>
            <Checkbox id="sheet-c1" name="remember" checked>Remember for headless.ly</Checkbox>
            <Checkbox id="sheet-c2" name="always">Always allow Susan to send renewal emails</Checkbox>
          </Section>
          <Section title="Identity">
            <Who name="Bryant Skarda" sub="bryant@driv.ly" right={<Link href="#">Switch</Link>} />
            <Who name="Bryant Skarda" sub="bryant@driv.ly" right={<WhoMeta>Confirmed 3 hours ago</WhoMeta>} />
            <AccountList>
              <AccountRow name="Bryant Skarda" email="bryant@driv.ly" lastUsedHere href="#" />
              <AccountRow name="Bryant Skarda" email="bryant@do.industries" sessionValue="sid_2" />
              <AnotherAccountRow href="#">Use another account</AnotherAccountRow>
            </AccountList>
            <div class="id-sheet__row">
              <Avatar name="Bryant Skarda" />
              <Avatar name="Nathan Clevenger" size={34} />
              <Avatar name="Photo" src="/og.png" />
              <Pill>Last used</Pill>
              <Pill accent>Accent</Pill>
            </div>
          </Section>
          <Section title="Wells">
            <DeviceCodeWell code="WDJB-MJHT" meta="macOS · Miami, FL · requested 1 min ago" />
            <Well>
              <KeyValues items={[{ k: 'Account', v: 'bryant@driv.ly' }, { k: 'Returns to', v: '127.0.0.1:57585', mono: true }]} />
            </Well>
            <QuoteWell>Our team uses Codex for the Drivly API work.</QuoteWell>
            <Well variant="tight">
              <KeyValue k="To" v="ops@acme.com" />
              <Excerpt>Hi Dana, your renewal is coming up on the 14th.</Excerpt>
              <Link href="#">View full email</Link>
            </Well>
            <Stats items={[{ n: '128', label: 'Contacts' }, { n: '14', label: 'Deals' }, { n: '3', label: 'Workflows' }]} footer="Sandbox ends in 18 hours" />
            <Meta icon="clock">Expires in 6 days</Meta>
          </Section>
          <Section title="Permissions and source">
            <PermissionList
              heading="Codex would like to"
              items={[
                { icon: 'user', title: 'See your name, email and photo', detail: 'Your profile from id.org.ai.', scope: 'openid profile email' },
                { icon: 'pen', title: 'Run Verbs that change your Startups', detail: 'Create, update and run Verbs.', scope: 'sb:do · resource https://api.sb', act: true, actNote: 'Changes are made in your name.' },
              ]}
            />
            <SourceRow
              display="chatgpt.com/oauth/codex/client.json"
              icon="globe"
              details={[{ k: 'Runs on', v: 'This computer' }, { k: 'Returns to', v: '127.0.0.1:57585', mono: true }]}
              links={[{ href: '#', label: 'Codex privacy policy' }, { href: '#', label: 'Codex terms' }]}
              copyValue="https://chatgpt.com/oauth/codex/client.json"
            />
            <SourceRow display="ed25519 · 7f3a…c21d" mono icon="key" details={[{ k: 'Host', v: 'bryant-mbp (macOS)' }]} copyValue="ed25519:7f3a…c21d" copied />
          </Section>
          <Section title="Notes, callouts, disclosure, code">
            <WarningCallout title="id.org.ai can't vouch for this app">Only continue if you trust it.</WarningCallout>
            <Note icon="lock">Your admin controls this account.</Note>
            <Disclosure summary="Developer details" open>
              <KeyValue k="error" v="invalid_request" mono />
              <CopyButton value="error: invalid_request" labelled />
            </Disclosure>
            <Pre>{'name: claim\non: push'}</Pre>
            <CodeBlock code="npx id.org.ai claim clm_7Hk2Qp9w" />
            <Step n={1} label="Run this in your repo">
              <CodeBlock code="npx id.org.ai claim clm_7Hk2Qp9w" copied />
            </Step>
            <StatusList items={[{ title: 'Waiting for a push', sub: 'Watching dot-org-ai/headless', current: true }, { title: 'Pending on a branch' }, { title: 'Claimed' }]} />
          </Section>
          <Section title="Foot pieces">
            <FootNote icon="shield">Never confirm a code someone sent you.</FootNote>
            <FootText>
              Wasn’t you? <Link href="#">Sign this device out</Link>
            </FootText>
            <Dotted />
            <Dotted label="or" />
            <Countdown secondsLeft={272} />
            <Countdown secondsLeft={42} urgent />
            <ResendTimer secondsLeft={42}>
              <button type="button" class="id-link">Resend code</button>
            </ResendTimer>
            <ResendTimer secondsLeft={0}>
              <button type="button" class="id-link">Resend code</button>
            </ResendTimer>
          </Section>
          <Section title="Icons">
            <div class="id-sheet__row">
              {ICONS.map((n) => (
                <span title={n} class="id-fg2">
                  <Icon name={n} size={16} />
                </span>
              ))}
            </div>
          </Section>
        </div>
      </Card>
    </Page>
  )
}
