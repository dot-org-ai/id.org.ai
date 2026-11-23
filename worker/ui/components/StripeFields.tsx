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
 * is the mount point for Stripe's Payment Element, never real card inputs:
 * the picture inside is aria-hidden, holds no form controls, and is replaced
 * when the element mounts.
 */
export function StripeFields({ publishableKey, clientSecret, mode, methods = ['Card', 'US bank account'] }: StripeFieldsProps): JSX.Element {
  return (
    <div class="id-well id-well--12" data-js="stripe-fields" data-publishable-key={publishableKey} data-client-secret={clientSecret} data-mode={mode}>
      <div data-stripe-mount hidden></div>
      <div class="id-stripe__picture" data-stripe-picture aria-hidden="true">
        {/* Stripe's Payment Element draws its own method tabs; the picture shows where they sit. */}
        <div class="id-seg">
          {methods.map((m, i) => (
            <span class={i === 0 ? 'id-seg__cell id-seg__cell--on' : 'id-seg__cell'}>{m}</span>
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
