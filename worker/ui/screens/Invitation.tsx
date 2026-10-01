/**
 * 2e · Accept invitation (docs/product-update/spec/screens.md#2e).
 *
 * `POST /invite/:token` with `decision=accept|decline`. 2e stays on id.org.ai
 * (motion.md#where-the-person-goes-next), so the form is a fetch-form
 * (worker/ui/client/lib/fetch-form.ts):
 *   - Join (`done="joined"`): the server normally answers `{redirect}` to 2c,
 *     which leaves at once. On a plain `{ok}` the joined result swaps in.
 *   - Decline (`deny`, `done="declined"`): `broken` at once, then the declined
 *     result once 1820ms have passed and the server agreed.
 * Both results ride along in <template data-state> elements on the live page,
 * and are states of their own: without JS the form posts and the server
 * renders the result (or continues to 2c).
 *
 * An invitation belongs to one email: when the signed-in account's email is
 * not the invited one, Join and Decline are both disabled (the server refuses
 * either from another account) and the who row's Switch becomes a button.
 */
import type { JSX } from 'hono/jsx/jsx-runtime'
import {
  Actions,
  Button,
  Card,
  CardFoot,
  CardHead,
  Connector,
  Em,
  FootText,
  KeyValues,
  Link,
  Note,
  Page,
  Stack,
  Well,
  Who,
  type TileContent,
} from '../components'

export type InvitationState = 'open' | 'joined' | 'declined'

export interface InvitationProps {
  /** `open` is the live form; `joined` and `declined` are the results. */
  state?: InvitationState
  inviter: { name: string }
  workspace: { name: string; tile: TileContent }
  /** The role offered, as shown: "Admin", "Member". */
  role: string
  invitedEmail: string
  /** "in 6 days" */
  expiresIn: string
  /** The signed-in identity. */
  account: { name: string; email: string; avatar?: string }
  /** `/account/choose?continue=/invite/:token` */
  switchHref: string
  /**
   * Where Join continues (through 2c): the workspace's app, or the id.org.ai
   * home. The joined result links here when the server didn't redirect.
   */
  continueHref: string
  /** `/invite/:token` */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

/** The article before a role, by its sound (as in the 8b email): "an Admin", "an Owner", "a Member", "a User". */
export function article(role: string): 'a' | 'an' {
  return /^[aeio]/i.test(role) ? 'an' : 'a'
}

export function emailMismatch(p: Pick<InvitationProps, 'account' | 'invitedEmail'>): boolean {
  return p.account.email.trim().toLowerCase() !== p.invitedEmail.trim().toLowerCase()
}

function FormBody({ p, mismatch }: { p: InvitationProps; mismatch: boolean }): JSX.Element {
  const who = (
    <Who
      name={p.account.name}
      sub={p.account.email}
      avatar={p.account.avatar}
      right={
        mismatch ? (
          <Button variant="secondary" size="sm" href={p.switchHref}>
            Switch account
          </Button>
        ) : (
          <Link href={p.switchHref}>Switch</Link>
        )
      }
    />
  )
  return (
    <Stack gap={22}>
      <CardHead
        connector={<Connector left={ORG} right={p.workspace.tile} />}
        title={`Join ${p.workspace.name}`}
        description={
          <>
            <Em>{p.inviter.name}</Em> invited you as {article(p.role)} <Em>{p.role}</Em>.
          </>
        }
      />
      <Well>
        <KeyValues
          items={[
            { k: 'Workspace', v: p.workspace.name },
            { k: 'Role', v: p.role },
            { k: 'Invited', v: p.invitedEmail },
            { k: 'Expires', v: p.expiresIn },
          ]}
        />
      </Well>
      {mismatch ? (
        <Stack gap={12}>
          {who}
          <Note icon="mail">
            This invitation is for <Em>{p.invitedEmail}</Em>. Switch to that account to join or decline.
          </Note>
        </Stack>
      ) : (
        who
      )}
    </Stack>
  )
}

function FormFoot({ mismatch }: { mismatch: boolean }): JSX.Element {
  return (
    <Actions>
      <Button variant="secondary" block name="decision" value="decline" disabled={mismatch} deny done="declined">
        Decline
      </Button>
      <Button variant="primary" block name="decision" value="accept" disabled={mismatch} busyLabel="Joining…" done="joined">
        Join workspace
      </Button>
    </Actions>
  )
}

function JoinedBody({ p }: { p: InvitationProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <CardHead
        connector={<Connector left={ORG} right={p.workspace.tile} state="ok" />}
        title={`Welcome to ${p.workspace.name}`}
        description={
          <>
            You joined as {article(p.role)} <Em>{p.role}</Em>.
          </>
        }
      />
    </Stack>
  )
}

function JoinedFoot({ p }: { p: InvitationProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>
        <Link href={p.continueHref}>{`Continue to ${p.workspace.name}`}</Link>
      </FootText>
    </div>
  )
}

function DeclinedBody({ p }: { p: InvitationProps }): JSX.Element {
  return (
    <Stack gap={22}>
      <CardHead
        connector={<Connector left={ORG} right={p.workspace.tile} state="fail" />}
        title="Invitation declined"
        description={
          <>
            You didn’t join <Em>{p.workspace.name}</Em>. You can close this tab.
          </>
        }
      />
    </Stack>
  )
}

function DeclinedFoot({ p }: { p: InvitationProps }): JSX.Element {
  return (
    <div class="id-fade">
      <FootText>{`Changed your mind? Ask ${p.inviter.name} to invite you again.`}</FootText>
    </div>
  )
}

/** A result rendered by the server (no JS, or the gallery): the same body and foot the templates swap in. */
function Result({ body, foot, status }: { body: JSX.Element; foot: JSX.Element; status: string }): JSX.Element {
  return (
    <Page narrow>
      <Card foot={<CardFoot>{foot}</CardFoot>}>
        {body}
        <span class="id-sr" role="status" data-status>
          {status}
        </span>
      </Card>
    </Page>
  )
}

export function Invitation(p: InvitationProps): JSX.Element {
  if (p.state === 'joined') return <Result body={<JoinedBody p={p} />} foot={<JoinedFoot p={p} />} status="Joined" />
  if (p.state === 'declined') return <Result body={<DeclinedBody p={p} />} foot={<DeclinedFoot p={p} />} status="Declined" />
  const mismatch = emailMismatch(p)
  return (
    <Page narrow>
      <form class="id-form" method="post" action={p.action} data-js="fetch-form">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <div data-region="foot">
                <FormFoot mismatch={mismatch} />
              </div>
              <template data-state="joined">
                <JoinedFoot p={p} />
              </template>
              <template data-state="declined">
                <DeclinedFoot p={p} />
              </template>
            </CardFoot>
          }
        >
          <div data-region="body">
            <FormBody p={p} mismatch={mismatch} />
          </div>
          <template data-state="joined">
            <JoinedBody p={p} />
          </template>
          <template data-state="declined">
            <DeclinedBody p={p} />
          </template>
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
