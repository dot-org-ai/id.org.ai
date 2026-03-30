'use client'

import 'iconify-icon'
import { Providers } from './providers'
import { MeshGradientBackground } from '@/components/backgrounds/mesh-gradient'

const oauthProviders = [
  {
    name: 'Continue with GitHub',
    icon: 'simple-icons:github',
    href: '/login?provider=GitHubOAuth',
  },
  {
    name: 'Continue with Google',
    icon: 'logos:google-icon',
    href: '/login?provider=GoogleOAuth',
  },
  {
    // TODO: Enable MicrosoftOAuth in WorkOS dashboard, then change to /login?provider=MicrosoftOAuth
    name: 'Continue with Microsoft',
    icon: 'logos:microsoft-icon',
    href: '/login?provider=authkit',
  },
  {
    // TODO: Enable AppleOAuth in WorkOS dashboard, then change to /login?provider=AppleOAuth
    name: 'Continue with Apple',
    icon: 'simple-icons:apple',
    href: '/login?provider=authkit',
  },
  {
    // TODO: Enable LinkedInOAuth in WorkOS dashboard, then change to /login?provider=LinkedInOAuth
    name: 'Continue with LinkedIn',
    icon: 'logos:linkedin-icon',
    href: '/login?provider=authkit',
  },
]

export function AuthHero() {
  return (
    <section className="bg-background relative min-h-screen flex flex-col">
      <MeshGradientBackground />
      {/* Centered hero content */}
      <div className="flex-1 flex items-center justify-center pt-32">
        <div className="relative w-full max-w-6xl px-6">
          <div className="grid gap-12 lg:grid-cols-2 lg:gap-20 items-center">
            {/* Left side - Hero content */}
            <div className="text-center lg:text-left flex flex-col justify-center">
              <h1 className="text-foreground font-semibold text-6xl sm:text-8xl">
                <span className="block">Humans.</span>
                <span className="block">Agents.</span>
                <span className="block">Identity.</span>
              </h1>
              <p className="text-muted-foreground mt-6 text-lg sm:text-xl">
                Simple, secure sign-in for humans <br/> and AI agents.
              </p>
            </div>

            {/* Right side - OAuth buttons */}
            <div className="border-border/50 rounded-xl border backdrop-blur-sm p-2 bg-card shadow-lg">
              <div className="grid grid-cols-1 gap-2">
                {oauthProviders.map((provider) => (
                  <a
                    key={provider.name}
                    href={provider.href}
                    className="group flex items-center justify-center gap-3 rounded-lg border border-transparent bg-foreground/5 px-4 py-3 text-foreground transition-all duration-200 hover:bg-white hover:border-border dark:bg-muted dark:hover:bg-muted/80 dark:hover:border-border dark:hover:text-accent-foreground"
                  >
                    <iconify-icon
                      icon={provider.icon}
                      width="20"
                      height="20"
                    />
                    <span className="text-sm font-medium">
                      {provider.name}
                    </span>
                  </a>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Providers at the bottom */}
      <div className="pb-8">
        <Providers />
      </div>

      {/* Decorative border lines */}
      {/* <div
        aria-hidden
        className="border-foreground/10 pointer-events-none absolute inset-0 mx-auto flex max-w-7xl justify-between border-x"
      >
        <div className="border-foreground/10 relative h-full w-2 border-r" />
        <div className="border-foreground/10 relative h-full w-2 border-l" />
      </div> */}
    </section>
  )
}
