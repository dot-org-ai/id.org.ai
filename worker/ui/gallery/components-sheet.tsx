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
import { CodeHint, FootLinks, OrgRow, ProviderAction, Resend } from '../components'
import {
  ActivityRow,
  AgentRow,
  Amount,
  Bar,
  CallResult,
  ChargeRow,
  Chip,
  CompareWell,
  FieldMapRow,
  HeaderStatus,
  Listening,
  MethodRow,
  MiniTile,
  PayLine,
  PlanPicker,
  PromptWell,
  SegTabs,
  Spend,
  SpendRow,
  StepItem,
  StepList,
  StripeFields,
  TermsAgree,
  Toggle,
  ToggleRow,
  Total,
} from '../components'

const ICONS: IconName[] = ['chev_r', 'chev_d', 'chev_ud', 'check', 'key', 'mail', 'copy', 'user', 'search', 'pen', 'laptop', 'terminal', 'shield', 'alert', 'clock', 'plus', 'globe', 'logout', 'lock', 'x', 'send', 'commit', 'building', 'bot', 'external', 'pause', 'play', 'trash', 'shield_check', 'card', 'bank', 'zap', 'flask', 'arrow_ur', 'layers', 'bell', 'fingerprint']
const STATES: ConnectorState[] = ['idle', 'connecting', 'done', 'broken', 'ok', 'fail', 'hold']

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
            <Resend availableIn={42} form="sheet-resend" />
            <Resend availableIn={0} form="sheet-resend" />
            <ProviderAction provider="github" href="#">
              Continue with GitHub
            </ProviderAction>
            <OrgRow name="Acme" sub="acme.com · Okta" />
            <CodeHint>Codes look like WDJB-MJHT and last 30 minutes.</CodeHint>
            <CodeHint error>That code didn’t match. Check the email and try again.</CodeHint>
            <FootLinks>
              <Link href="#">Use a passkey instead</Link>
              <Link href="#">Use a recovery code</Link>
            </FootLinks>
            <RadioGroup legend="How far to sign out" layout="stack" hideLabel>
              <RadioCard id="sheet-s1" name="sheet-scope" value="app" checked title="This app" description="Sign out of headless.ly only." />
            </RadioGroup>
          </Section>
          <Section title="Agent setup: header status, mini tile, chip">
            <div class="id-sheet__row">
              <HeaderStatus tone="ok" verb="Updated" seconds={4} />
              <HeaderStatus tone="warn" verb="Last seen" seconds={600} />
              <MiniTile content={{ kind: 'icon', icon: 'bot' }} />
              <MiniTile content={{ kind: 'monogram', text: 'Cx' }} />
              <Chip>Setting up</Chip>
              <Chip>Default</Chip>
            </div>
          </Section>
          <Section title="Step list: every step state">
            <StepList label="Setup steps">
              <StepItem state="done" title="Agent approved" when="2:14 PM" detail="Trusted in Drivly, up to $500 a month." />
              <StepItem state="done" title="Test key issued" when="2:14 PM" />
              <StepItem state="now" title="First real call" when="Now" detail="Waiting for Claude Code to call Auto.dev with the test key.">
                <Listening text="Listening on test key …a91c" elapsed="0:42" note="A call copied from the docs example doesn’t count." />
              </StepItem>
              <StepItem state="you" title="Approve spending" when="Waiting on you" detail="Claude Code subscribes inside the limit you set." />
              <StepItem state="fail" title="Live key" when="Declined" detail="Drivly’s card ending 4417 was declined." />
              <StepItem state="held" title="First real email" when="Paused" tag="apis.email" detail="Calls are refused while it’s paused." />
              <StepItem state="todo" title="Ready for production" detail="Auto.dev checks that it backs off and retries." />
            </StepList>
          </Section>
          <Section title="Evidence">
            <CallResult
              method="GET"
              path="/vin/1HGCM82633A004352"
              status={200}
              result="212 ms"
              rows={[['Vehicle', '2003 Honda Accord Cpe'], ['Trim', 'EX Auto V6 w/Leather'], ['Engine', '3.0, V6 Cylinder Engine']]}
              link={{ href: '#', label: 'View full response' }}
            />
            <CallResult method="GET" path="/vin/1HGCM82633A00435" status={400} result="INVALID_VIN_FORMAT" />
            <PromptWell label="Paste this to Claude Code" text="Continue the Auto.dev setup. Read apis.ax/setup/su_8f2k and do what “next” says." />
            <PromptWell label="Give this to your agent" text="Set up Auto.dev through apis.ax. Follow [AGENT GUIDE URL]." copied />
            <CompareWell
              rows={[
                { name: 'Decode a VIN', text: '250 of 250 match', state: 'ok' },
                { name: 'Search listings', text: '181 of 250 so far', state: 'running' },
              ]}
              note="A difference stops the switch and shows you both answers."
            />
            <Well variant="default">
              <FieldMapRow id="sheet-map1" name="map_lead_src" column="lead_src" options={['Source', 'A new field: lead_src', 'Skip this column']} value="Source" />
              <FieldMapRow id="sheet-map2" name="map_acct_mgr" column="acct_mgr" options={['Owner', 'A new field: acct_mgr', 'Skip this column']} value="Owner" />
            </Well>
          </Section>
          <Section title="Paying: pays-with line, spend block, terms, toggle">
            <PayLine method="Visa ending 4417" href="#" addHref="#" />
            <PayLine href="#" addHref="#" />
            <Spend id="sheet-spend" planPrice="$299" limit={{ options: [null, 10000, 50000, 100000, 200000, 500000], value: null }} alerts={{ marks: [10000, 50000, 100000, 200000, 500000], on: true, open: true }} />
            <Spend id="sheet-alerts-only" alerts={{ marks: [10000, 50000, 100000, 200000, 500000], on: false }} />
            <Spend id="sheet-limit-only" planPrice="$299" limit={{ options: [null, 10000, 50000], value: 50000 }} />
            <div class="id-sheet__row">
              <Toggle id="sheet-toggle-on" name="t1" checked label="On" />
              <Toggle id="sheet-toggle-off" name="t2" label="Off" />
            </div>
            <ToggleRow id="sheet-receipt" name="receipts" checked title="Email a receipt for every charge" sub="Sent to bryant@driv.ly." />
            <Checkbox id="sheet-c3" name="cancel_sub" detail="Left on, Growth keeps billing Drivly at $299 a month.">Also cancel the Auto.dev subscription</Checkbox>
            <Checkbox id="sheet-c4" name="agents_can_charge" checked detail="Only agents you approved, and only inside their limit.">Agents can charge this</Checkbox>
          </Section>
          <Section title="Terms: the primary action waits for the tick">
            <Card
              foot={
                <CardFoot>
                  <TermsAgree id="sheet-terms" product="Auto.dev" termsHref="https://www.auto.dev/terms" privacyHref="https://www.auto.dev/privacy" />
                  <Actions>
                    <Button variant="secondary" block type="button">Not now</Button>
                    <Button variant="primary" block type="button" needsTerms>Approve Growth</Button>
                  </Actions>
                </CardFoot>
              }
            >
              <Note>Unticked on load: the button stays disabled until the line is ticked.</Note>
            </Card>
          </Section>
          <Section title="Plans: radio group, separate disclosure, billing toggle">
            <Card
              foot={
                <CardFoot>
                  <Actions>
                    <Button variant="secondary" block type="button">Cancel</Button>
                    <Button variant="primary" block type="button" follows={{ control: 'sheet-plan', template: 'Continue with {label}' }}>Continue with Growth</Button>
                  </Actions>
                </CardFoot>
              }
            >
              <PlanPicker
                name="sheet-plan"
                plans={[
                  { id: 'free', name: 'Free', price: '$0', summary: '1,000 calls a month · 5 requests a second', included: [{ label: 'Global VIN Decode', value: 'Included' }, { label: 'MCP server, CLI and SDK' }], selected: false, open: false },
                  { id: 'growth', name: 'Growth', price: '$299', priceYearly: '$249', priceNote: 'a month + data fees', summary: 'Unlimited calls · 10 requests a second', included: [{ label: 'Global VIN Decode', value: '$0.0025 a call' }, { label: 'Vehicle Listings', value: '$0.0015' }, { label: 'Priority email support' }], selected: true, open: true },
                  { id: 'scale', name: 'Scale', price: '$599', priceYearly: '$499', priceNote: 'a month + data fees', summary: 'Unlimited calls · 50 requests a second', included: [{ label: 'Everything in Growth, at lower data fees' }], selected: false, open: false },
                ]}
              />
            </Card>
          </Section>
          <Section title="Payment method: segmented tabs and Stripe’s fields">
            <SegTabs legend="Payment method type" name="sheet-method" selected="card" options={[{ value: 'card', label: 'Card' }, { value: 'bank', label: 'Bank account' }, { value: 'link', label: 'Link' }]} />
            <StripeFields />
          </Section>
          <Section title="Agents and activity">
            <AgentRow
              tile={{ kind: 'icon', icon: 'bot' }}
              name="Claude Code"
              line="Trusted · active 2 min ago"
              open
              facts={[{ k: 'Identity', v: 'ed25519 · 7f3a…c21d', mono: true }, { k: 'Spent this month', v: '$299 of $500' }]}
              connections={[
                { name: 'Auto.dev', state: 'Live · key ends in 4f2a', link: { href: '#', label: 'Open dashboard' } },
                { name: 'apis.email', state: 'Setting up · first real call', link: { href: '#', label: 'Watch' } },
              ]}
              actions={
                <Actions>
                  <Button variant="secondary" block href="#" icon="pause">Pause</Button>
                  <Button variant="secondary" block href="#" icon="trash">Remove</Button>
                </Actions>
              }
              links={[{ href: '#', label: 'View activity' }, { href: '#', label: 'Spending' }]}
            />
            <AgentRow tile={{ kind: 'monogram', text: 'Cx' }} name="Codex" chip="Setting up" line="Sandboxed · this computer" />
            <div>
              <ActivityRow icon="shield_check" text="Passed the production check on Auto.dev" when="2:17 PM" />
              <ActivityRow icon="card" text="Subscribed to Growth at $299 a month" more="Spent money, inside your $500 limit." money when="2:17 PM" />
              <ActivityRow icon="zap" text="Made its first real call to Auto.dev" more="GET /vin/1HGCM82633A004352 · 200" mono when="2:16 PM" />
            </div>
          </Section>
          <Section title="Money">
            <Total amount="$441.20" note="of $850 your agents may spend · $41.20 still running" />
            <div>
              <SpendRow tile={{ kind: 'icon', icon: 'bot' }} name="Claude Code" amount="$340.20" limit="$500" percent={68} line="Auto.dev" href="#" />
              <SpendRow tile={{ kind: 'monogram', text: 'Su' }} name="Susan" amount="$250.00" limit="$250" percent={100} line="headless.ly · at its limit" href="#" />
            </div>
            <div>
              <ChargeRow name="Auto.dev · data fees" chip="Running" line="16,480 calls so far · billed Dec 22" amount="$41.20" href="#" />
              <ChargeRow name="Auto.dev · Growth" line="Nov 22 · Claude Code" amount="$299.00" href="#" />
            </div>
            <MethodRow icon="card" title="Visa ending 4417" chip="Default" sub="Expires 08/28 · charged by 3 agents" link={{ href: '#', label: 'Replace' }} />
            <MethodRow icon="bank" title="Bank account ending 2210" sub="Agents can’t charge this" link={{ href: '#', label: 'Allow agents' }} />
            <div class="id-sheet__row">
              <Amount amount="$500.00" of="$500" />
            </div>
            <Bar percent={40} />
            <Bar percent={100} full />
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
