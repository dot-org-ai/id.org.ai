import type { JSX } from 'hono/jsx/jsx-runtime'
import { Icon } from '../icons'

export interface StripeFieldsProps {
  /**
   * Stripe's publishable key and the SetupIntent's client secret. With both,
   * stripe-fields.ts mounts Stripe's Payment Element here, themed from the
   * tokens. Without them (the gallery, and until the backend exists) the box
   * shows a picture of it.
   */
  publishableKey?: string
  clientSecret?: string
  /** Without a client secret: let Stripe render for saving a method (`setup`) before any intent exists. */
  mode?: 'setup'
  /**
   * The methods Stripe will offer as tabs, in order, for the picture. Which ones a person really
   * sees is Stripe's decision at mount. Link is not a tab: Stripe offers it inside the card form.
   */
  methods?: string[]
}

/**
 * How Stripe's element is made to look like ours: the Appearance API's `variables` and
 * `rules`, written against our tokens. The mount script swaps each `var(--id-…)` for the
 * token's value and turns every colour into a plain red-green-blue one, because Stripe drops
 * colours it can't read (our token format in a border, a translucent colour or a variable in
 * a colour setting) and falls back to its own. Checked against the real element with test-visual/stripe-live-measure.mjs.
 *
 * What Stripe does not let us change, so we follow it instead: each tab is an icon over its
 * label, about 52px tall (the icon can't be hidden), and Link is offered inside the card form.
 */
const FIELD = { backgroundColor: 'var(--id-panel)', border: '1px solid var(--id-line-2)', boxShadow: 'var(--id-sh-input)', padding: '12px 14px', lineHeight: '18px', color: 'var(--id-fg)' }
const TAB = { border: '1px solid transparent', backgroundColor: 'transparent', boxShadow: 'none', color: 'var(--id-fg-2)', borderRadius: 'var(--id-r-sm)', padding: '8px 12px', fontSize: '13px', fontWeight: '500' }
const TAB_ON = { ...TAB, backgroundColor: 'var(--id-raised)', border: '1px solid var(--id-line-2)', boxShadow: 'var(--id-sh-ctrl)', color: 'var(--id-fg)' }
export const STRIPE_APPEARANCE = {
  theme: 'night',
  variables: {
    fontFamily: 'var(--id-font)',
    fontSizeBase: '14px',
    fontSizeSm: '13px',
    borderRadius: 'var(--id-r-control)',
    gridRowSpacing: '12px',
    gridColumnSpacing: '12px',
    colorBackground: 'var(--id-panel)',
    colorText: 'var(--id-fg)',
    colorTextSecondary: 'var(--id-fg-2)',
    colorTextPlaceholder: 'var(--id-fg-3)',
    colorPrimary: 'var(--id-fg)',
    colorDanger: 'var(--id-accent)',
    iconColor: 'var(--id-fg-3)',
    tabIconColor: 'var(--id-fg-2)',
    tabIconSelectedColor: 'var(--id-fg)',
  },
  rules: {
    '.Label': { fontSize: '13px', fontWeight: '500', lineHeight: '17px', color: 'var(--id-fg-2)', marginBottom: '6px' },
    '.Input': FIELD,
    '.Input:focus': { ...FIELD, border: '1px solid var(--id-select)', boxShadow: 'var(--id-sh-input), var(--id-ring)', outline: 'none' },
    '.Input--invalid': { ...FIELD, border: '1px solid var(--id-accent)' },
    '.Tab': TAB,
    '.Tab:hover': { ...TAB, color: 'var(--id-fg)' },
    '.Tab:focus': { ...TAB, boxShadow: 'var(--id-ring)' },
    '.Tab--selected': TAB_ON,
    '.Tab--selected:hover': TAB_ON,
    '.Tab--selected:focus': { ...TAB_ON, boxShadow: 'var(--id-sh-ctrl), var(--id-ring)' },
    '.TabLabel': { fontSize: '13px', fontWeight: '500' },
    '.TermsText': { fontSize: '12px', lineHeight: '17px', color: 'var(--id-fg-3)' },
    '.Error': { fontSize: '12px', lineHeight: '18px', color: 'var(--id-accent)' },
  },
} as const

function Pictured({ label, placeholder, value, chevron }: { label: string; placeholder?: string; value?: string; chevron?: boolean }): JSX.Element {
  return (
    <div class="id-stripe__field">
      <span class="id-label">{label}</span>
      <span class={value ? 'id-stripe__box id-stripe__box--value' : 'id-stripe__box'}>
        <span class="id-stripe__text">{value ?? placeholder}</span>
        {chevron ? <Icon name="chev_ud" size={14} /> : null}
      </span>
    </div>
  )
}

/**
 * Card fields are always Stripe's (HANDOFF.md section 1; STRIPE.md 19a). This
 * is the mount point for Stripe's Payment Element, never real card inputs. Stripe's fields sit
 * straight on the card, like every other field here, with no box of their own around them:
 * the picture inside is aria-hidden, holds no form controls, and is replaced
 * when the element mounts.
 */
export function StripeFields({ publishableKey, clientSecret, mode, methods = ['Card', 'US bank account'] }: StripeFieldsProps): JSX.Element {
  return (
    <div class="id-stripe" data-js="stripe-fields" data-publishable-key={publishableKey} data-client-secret={clientSecret} data-mode={mode} data-appearance={publishableKey ? JSON.stringify(STRIPE_APPEARANCE) : undefined}>
      <div data-stripe-mount hidden></div>
      <div class="id-stripe__picture" data-stripe-picture aria-hidden="true">
        {/* Stripe's Payment Element draws its own method tabs, as icon-over-label tiles; the picture shows the same. */}
        <div class="id-stripe__tabs">
          {methods.map((m, i) => (
            <span class={i === 0 ? 'id-stripe__tab id-stripe__tab--on' : 'id-stripe__tab'}>
              <Icon name={/bank/i.test(m) ? 'bank' : 'card'} size={16} />
              {m}
            </span>
          ))}
        </div>
        <Pictured label="Card number" placeholder="1234 1234 1234 1234" />
        <div class="id-stripe__pair">
          <Pictured label="Expiration date" placeholder="MM / YY" />
          <Pictured label="Security code" placeholder="CVC" />
        </div>
        <div class="id-stripe__pair">
          <Pictured label="Country" value="United States" chevron />
          <Pictured label="ZIP code" placeholder="12345" />
        </div>
      </div>
      <span class="id-sr" data-stripe-picture>
        Stripe’s card fields load here.
      </span>
      <div class="id-stripe__note">
        <Icon name="lock" size={14} />
        <span>These fields are Stripe’s. id.org.ai never sees your card number.</span>
      </div>
    </div>
  )
}
