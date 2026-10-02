import type { Child } from 'hono/jsx'
import type { JSX } from 'hono/jsx/jsx-runtime'
import { LINKS } from '../links'
import { OrgMark } from './OrgMark'

export interface HeaderProps {
  /** Replaces the id.org.ai brand (branded first-party sign-in, 1g). */
  brand?: Child
  /** Right-hand slot: usually empty (the phone action approval puts its countdown here). */
  right?: Child
}

export function Header({ brand, right }: HeaderProps): JSX.Element {
  return (
    <header class="id-header">
      {brand ?? (
        <a class="id-brand" href={LINKS.home}>
          <OrgMark size={18} />
          <span>id.org.ai</span>
        </a>
      )}
      {right}
    </header>
  )
}

export interface AppBrandProps {
  name: string
  /** 1–2 letters, shown until the app's own mark exists (logos.md). */
  monogram: string
  /** A first-party brand mark under /brand/ (worker/ui/static/brand/). */
  markUrl?: string
  href?: string
}

/** 1g's header brand: the app's 28px tile, then its name. */
export function AppBrand({ name, monogram, markUrl, href }: AppBrandProps): JSX.Element {
  return (
    <a class="id-brand id-brand--app" href={href ?? LINKS.home}>
      <div class="id-apptile-sm">{markUrl ? <img src={markUrl} alt="" width={28} height={28} decoding="async" /> : monogram}</div>
      <span>{name}</span>
    </a>
  )
}
