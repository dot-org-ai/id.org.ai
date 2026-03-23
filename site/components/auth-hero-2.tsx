'use client'

import 'iconify-icon'
import { Providers } from './providers'

const oauthProviders = [
  {
    name: 'Sign up with GitHub',
    icon: 'simple-icons:github',
    href: '#',
  },
  {
    name: 'Continue with Google',
    icon: 'logos:google-icon',
    href: '#',
  },
  {
    name: 'Continue with Microsoft',
    icon: 'logos:microsoft-icon',
    href: '#',
  },
  {
    name: 'Continue with Apple',
    icon: 'simple-icons:apple',
    href: '#',
  },
  {
    name: 'Login with X',
    icon: 'simple-icons:x',
    href: '#',
  },
  {
    name: 'Connect LinkedIn',
    icon: 'logos:linkedin-icon',
    href: '#',
  },
]

export function AuthHero2() {
  return (
    <section className="bg-background relative min-h-screen flex flex-col">
      <div className="flex-1 flex flex-col items-center justify-center">
        <div className="relative text-center">
        <div className="px-6">
          <h1 className="text-foreground text-5xl font-bold tracking-tight sm:text-6xl">
            Humans. Agents. Auth.
          </h1>
          <p className="text-muted-foreground mx-auto mt-4 max-w-xl text-balance md:text-lg">
            Simple, secure sign-in for humans and AI agents.
          </p>
        </div>
        <div className="relative border-foreground/5 mt-8 border-y w-screen border-dashed">
          <div className="pointer-events-none absolute -top-px left-0 z-10 h-px w-24 bg-linear-to-r from-background to-transparent" />
          <div className="pointer-events-none absolute -top-px right-0 z-10 h-px w-24 bg-linear-to-l from-background to-transparent" />
          <div className="pointer-events-none absolute -bottom-px left-0 z-10 h-px w-24 bg-linear-to-r from-background to-transparent" />
          <div className="pointer-events-none absolute -bottom-px right-0 z-10 h-px w-24 bg-linear-to-l from-background to-transparent" />
          <div className="mx-auto max-w-5xl px-[9px]">
            <div className="bg-background grid grid-cols-1 items-center justify-center gap-1 p-1 sm:grid-cols-3">
              {oauthProviders.map((provider) => (
                <a
                  key={provider.name}
                  href={provider.href}
                  className="flex h-14 items-center justify-center gap-3 rounded bg-foreground/5 px-6 text-foreground transition-colors duration-200 hover:bg-foreground/10 dark:bg-accent/30 dark:hover:bg-card/80 dark:hover:text-accent-foreground"
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
      <div className="pb-8">
        <Providers />
      </div>
      <div
        aria-hidden
        className="border-foreground/5 pointer-events-none absolute inset-x-0 top-20 bottom-0 mx-auto flex max-w-5xl justify-between border-x"
      >
        {/* Left outer border fade */}
        <div className="absolute -left-px top-0 z-10 h-24 w-px bg-linear-to-b from-background to-transparent" />
        <div className="absolute -left-px bottom-0 z-10 h-24 w-px bg-linear-to-t from-background to-transparent" />
        {/* Right outer border fade */}
        <div className="absolute -right-px top-0 z-10 h-24 w-px bg-linear-to-b from-background to-transparent" />
        <div className="absolute -right-px bottom-0 z-10 h-24 w-px bg-linear-to-t from-background to-transparent" />
        <div className="border-foreground/5 relative h-full w-2 border-r">
          {/* Left inner border fade */}
          <div className="absolute -right-px top-0 z-10 h-24 w-px bg-linear-to-b from-background to-transparent" />
          <div className="absolute -right-px bottom-0 z-10 h-24 w-px bg-linear-to-t from-background to-transparent" />
        </div>
        <div className="border-foreground/5 relative h-full w-2 border-l">
          {/* Right inner border fade */}
          <div className="absolute -left-px top-0 z-10 h-24 w-px bg-linear-to-b from-background to-transparent" />
          <div className="absolute -left-px bottom-0 z-10 h-24 w-px bg-linear-to-t from-background to-transparent" />
        </div>
      </div>
    </section>
  )
}
