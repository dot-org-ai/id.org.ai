"use client";

import "iconify-icon";
import { Providers } from "./providers";
import { MeshGradientBackground } from '@/components/backgrounds/mesh-gradient'

const oauthProviders = [
  {
    name: "Continue with GitHub",
    icon: "simple-icons:github",
    href: "#",
  },
  {
    name: "Continue with Google",
    icon: "logos:google-icon",
    href: "#",
  },
  {
    name: "Continue with Microsoft",
    icon: "logos:microsoft-icon",
    href: "#",
  },
  {
    name: "Continue with Apple",
    icon: "simple-icons:apple",
    href: "#",
  },
  {
    name: "Continue with X",
    icon: "simple-icons:x",
    href: "#",
  },
  {
    name: "Continue with LinkedIn",
    icon: "logos:linkedin-icon",
    href: "#",
  },
];

export function AuthHero3() {
  return (
    <section className="bg-background relative min-h-screen flex flex-col">
        <MeshGradientBackground />
      <div className="flex-1 flex flex-col items-center justify-center pt-32 sm:pt-0">
        <div className="relative text-center">
          <div className="px-6">
            <h1 className="text-foreground text-6xl font-semibold sm:text-7xl">
              <span className="block">Humans.</span>
              <span className="block">Agents.</span>
              <span className="block">Auth.</span>
            </h1>
            <p className="text-muted-foreground mx-auto mt-4 max-w-xl text-balance md:text-lg">
              Simple, Secure Sign-in for Humans and AI Agents.
            </p>
          </div>
          <div className="relative border-foreground/10 mt-8 border-y w-screen border-dashed sm:mask-[linear-gradient(to_right,transparent,black_10%,black_90%,transparent)]">
            <div className="mx-auto max-w-5xl px-[9px]">
              <div className="bg-background/70 dark:bg-background/20 grid grid-cols-1 items-center justify-center gap-1 p-1 sm:grid-cols-2 lg:grid-cols-3">
                {oauthProviders.map((provider) => (
                  <a
                    key={provider.name}
                    href={provider.href}
                    className="flex h-16 sm:h-12 items-center justify-center gap-3 rounded border border-transparent bg-foreground/5 px-6 text-foreground transition-colors duration-200 hover:bg-white hover:border-border dark:bg-card dark:hover:bg-card/80 dark:hover:border-border dark:hover:text-accent-foreground"
                  >
                    <iconify-icon icon={provider.icon} width="20" height="20" />
                    <span className="text-base sm:text-sm font-medium">{provider.name}</span>
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
        style={{
          maskImage: "linear-gradient(to bottom, transparent, black 25%, black 75%, transparent)",
          WebkitMaskImage: "linear-gradient(to bottom, transparent, black 25%, black 75%, transparent)",
        }}
      >
        <div className="border-foreground/5 relative h-full w-2 border-r" />
        <div className="border-foreground/5 relative h-full w-2 border-l" />
      </div>
    </section>
  );
}
