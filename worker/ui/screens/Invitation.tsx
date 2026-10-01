/**
 * 2e · Accept invitation (docs/product-update/spec/screens.md#2e).
 *
 * `POST /invite/:token` with `decision=accept|decline`. Accepting continues to
 * 2c; declining renders the short confirmation (`state: 'declined'`) in place.
 * An invitation belongs to one email: when the signed-in account's email is not
 * the invited one, Join is disabled and the who row's Switch becomes a button.
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

export type InvitationState = 'open' | 'declined'

export interface InvitationProps {
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
  /** `/invite/:token` */
  action: string
  csrf: string
}

const ORG: TileContent = { kind: 'org' }

/** "an Admin", "a Member". */
function withArticle(role: string): string {
  return /^[aeiou]/i.test(role) ? 'an' : 'a'
}

export function emailMismatch(p: Pick<InvitationProps, 'account' | 'invitedEmail'>): boolean {
  return p.account.email.trim().toLowerCase() !== p.invitedEmail.trim().toLowerCase()
}

function Declined({ p }: { p: InvitationProps }): JSX.Element {
  return (
    <Page>
      <Card
        foot={
          <CardFoot>
            <FootText>{`Changed your mind? Ask ${p.inviter.name} to invite you again.`}</FootText>
          </CardFoot>
        }
      >
        <CardHead
          connector={<Connector left={ORG} right={p.workspace.tile} state="fail" />}
          title="Invitation declined"
          description={
            <>
              You didn’t join <Em>{p.workspace.name}</Em>. You can close this tab.
            </>
          }
        />
        <span class="id-sr" role="status" data-status>
          Declined
        </span>
      </Card>
    </Page>
  )
}

export function Invitation(p: InvitationProps): JSX.Element {
  if (p.state === 'declined') return <Declined p={p} />
  const mismatch = emailMismatch(p)
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
    <Page>
      <form class="id-form" method="post" action={p.action} data-js="submit">
        <input type="hidden" name="csrf" value={p.csrf} />
        <Card
          foot={
            <CardFoot>
              <Actions>
                <Button variant="secondary" block name="decision" value="decline">
                  Decline
                </Button>
                <Button variant="primary" block name="decision" value="accept" disabled={mismatch} busyLabel="Joining…">
                  Join workspace
                </Button>
              </Actions>
            </CardFoot>
          }
        >
          <CardHead
            connector={<Connector left={ORG} right={p.workspace.tile} />}
            title={`Join ${p.workspace.name}`}
            description={
              <>
                <Em>{p.inviter.name}</Em> invited you as {withArticle(p.role)} <Em>{p.role}</Em>.
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
                This invitation is for <Em>{p.invitedEmail}</Em>. Switch to that account to join.
              </Note>
            </Stack>
          ) : (
            who
          )}
          <span class="id-sr" role="status" data-status></span>
        </Card>
      </form>
    </Page>
  )
}
