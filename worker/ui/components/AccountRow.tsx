import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'
import { Avatar } from './Avatar'
import { Pill } from './Pill'

export interface AccountRowProps {
  name: string
  email: string
  avatar?: string
  lastUsedHere?: boolean
  /** A link row (GET), or a submit button posting `session=<value>` in the chooser form. */
  href?: string
  sessionValue?: string
}

/** An account in the chooser (components.md#account-row-account-chooser). */
export function AccountRow({ name, email, avatar, lastUsedHere, href, sessionValue }: AccountRowProps): JSX.Element {
  const inner = (
    <>
      <Avatar name={name} email={email} src={avatar} size={34} />
      <span class="id-account__text">
        <span class="id-account__name">
          {name}
          {lastUsedHere ? <Pill normalLine>Last used here</Pill> : null}
        </span>
        <span class="id-account__email">{email}</span>
      </span>
      <Icon name="chev_r" size={16} class="id-account__chev" />
    </>
  )
  if (href !== undefined) {
    return (
      <a class="id-account" href={href}>
        {inner}
      </a>
    )
  }
  return (
    <button class="id-account" type="submit" name="session" value={sessionValue}>
      {inner}
    </button>
  )
}

/** "Use another account": the same size, transparent, dashed, no shadow. */
export function AnotherAccountRow({ href, children }: { href: string; children: string }): JSX.Element {
  return (
    <a class="id-account id-account--another" href={href}>
      <span class="id-account__plus">
        <Icon name="plus" size={18} />
      </span>
      {children}
    </a>
  )
}

export function AccountList({ children }: { children: JSX.Element | JSX.Element[] }): JSX.Element {
  return <div class="id-accounts">{children}</div>
}
