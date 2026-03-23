'use client'

import 'iconify-icon'
import { Stripe } from '@/components/logos/stripe'
import { WorkOS } from '@/components/logos/workos'
import { Do } from '@/components/logos/do'

const authProviders = [
  {
    name: 'Cloudflare',
    icon: 'simple-icons:cloudflare',
    showName: true,
    width: 24,
    height: 24,
  },
  {
    name: 'WorkOS',
    Component: WorkOS,
    showName: false,
    width: 80,
    height: 16,
  },
  {
    name: '.do',
    Component: Do,
    showName: false,
    width: 48,
    height: 24,
  },
  {
    name: 'Auth0',
    icon: 'simple-icons:auth0',
    showName: true,
    width: 24,
    height: 24,
  },
  {
    name: 'Stripe',
    Component: Stripe,
    showName: false,
    width: 50,
    height: 20,
  },
]

export function Providers() {
  return (
    <div className="mx-auto max-w-2xl pt-16 pb-8 px-6">
      <p className="text-muted-foreground text-center text-sm mb-6">
        Built on trusted standards
      </p>
      <div className="grid grid-cols-2 place-items-center gap-8 px-10 pt-4 sm:px-0 sm:pt-0 text-foreground opacity-40 sm:flex sm:flex-wrap sm:justify-center sm:gap-12">
        {authProviders.map((provider) => (
          <div
            key={provider.name}
            className="flex items-center justify-center gap-2 text-foreground scale-125 sm:scale-100"
          >
            {provider.Component ? (
              <provider.Component
                width={provider.width}
                height={provider.height}
              />
            ) : (
              <iconify-icon
                icon={provider.icon!}
                width={String(provider.width)}
                height={String(provider.height)}
                class="text-foreground"
              />
            )}
            {provider.showName && (
              <span className="text-foreground text-sm font-medium">
                {provider.name}
              </span>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
