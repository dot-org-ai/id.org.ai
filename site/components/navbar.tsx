'use client'

import { useEffect, useState } from 'react'
import Link from 'next/link'
import { OrgLogo } from '@/components/logos/org-logo'
import { Button } from '@/components/ui/button'
import { AnimatedThemeToggler } from '@/components/ui/animated-theme-toggler'

interface MeResponse {
  authenticated: boolean
  user?: {
    id: string
    email?: string
    name?: string
    githubUsername?: string
    org?: { id: string; name?: string }
  }
}

export function Navbar() {
  const [scrolled, setScrolled] = useState(false)
  const [me, setMe] = useState<MeResponse | null>(null)

  useEffect(() => {
    const handleScroll = () => {
      setScrolled(window.scrollY > 10)
    }
    window.addEventListener('scroll', handleScroll)
    return () => window.removeEventListener('scroll', handleScroll)
  }, [])

  useEffect(() => {
    fetch('/api/me', { credentials: 'include' })
      .then((r) => r.json())
      .then((data) => setMe(data as MeResponse))
      .catch(() => setMe({ authenticated: false }))
  }, [])

  const displayName = me?.user?.name || me?.user?.email || me?.user?.githubUsername || 'Account'

  return (
    <nav className={`pointer-events-none fixed inset-x-0 top-0 z-50 transition-colors duration-200 ${scrolled ? 'bg-background pointer-events-auto' : ''}`}>
      <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-4">
        <Link href="/" className="pointer-events-auto flex items-center gap-2">
          <OrgLogo width={32} height={32} />
          <span className="text-foreground font-medium">id.org.ai</span>
        </Link>
        <div className="pointer-events-auto flex items-center gap-4">
          <AnimatedThemeToggler className="p-2 hover:text-foreground/70 transition-colors [&_svg]:size-4 cursor-pointer" />
          {me?.authenticated ? (
            <div className="flex items-center gap-3">
              <span className="text-sm text-muted-foreground">{displayName}</span>
              <Button variant="outline" asChild>
                <a href="/logout">Logout</a>
              </Button>
            </div>
          ) : (
            <Button variant="outline" asChild>
              <a href="/login">Login</a>
            </Button>
          )}
        </div>
      </div>
    </nav>
  )
}
