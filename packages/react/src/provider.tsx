'use client'

import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { createIdClient } from './client'
import { IdAuthContext, IdConfigContext } from './context'
import {
  generateCodeChallenge,
  generateCodeVerifier,
  getAndClearNonce,
  getAndClearVerifier,
  storeNonce,
  storeVerifier,
} from './pkce'
import type { AuthUser, IdProviderProps } from './types'

const DEFAULT_BASE_URL = 'https://id.org.ai'

export function IdProvider({
  clientId,
  baseUrl = DEFAULT_BASE_URL,
  redirectUri,
  onRedirectCallback,
  children,
}: IdProviderProps) {
  const queryClient = useMemo(
    () =>
      new QueryClient({
        defaultOptions: {
          queries: {
            staleTime: 30_000,
            retry: 1,
            refetchOnWindowFocus: false,
          },
        },
      }),
    [],
  )

  const [user, setUser] = useState<AuthUser | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<Error | null>(null)
  const client = useMemo(() => createIdClient(baseUrl), [baseUrl])
  const onRedirectCallbackRef = useRef(onRedirectCallback)
  onRedirectCallbackRef.current = onRedirectCallback

  const resolvedRedirectUri = useMemo(() => {
    if (typeof window === 'undefined') return ''
    return redirectUri
      ? redirectUri.startsWith('http')
        ? redirectUri
        : `${window.location.origin}${redirectUri}`
      : `${window.location.origin}/callback`
  }, [redirectUri])

  // Access token query — auto-refreshes before expiry
  const { data: accessToken = null } = useQuery(
    {
      queryKey: ['id.org.ai', 'accessToken'],
      queryFn: () => client.fetchWidgetToken(),
      enabled: !!user,
      staleTime: 4 * 60 * 1000, // 4 minutes (tokens expire in 5)
    },
    queryClient,
  )

  // Listen for session refresh events (e.g., after org switch)
  useEffect(() => {
    const handleRefresh = () => {
      queryClient.invalidateQueries({ queryKey: ['id.org.ai'] })
      client
        .fetchSession()
        .then((session) => {
          setUser(session.user)
        })
        .catch(() => {})
    }
    window.addEventListener('id.org.ai:session-refresh', handleRefresh)
    return () => window.removeEventListener('id.org.ai:session-refresh', handleRefresh)
  }, [client, queryClient])

  // Handle OAuth callback if we're on the redirect URI with a code
  useEffect(() => {
    if (typeof window === 'undefined') return

    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const stateParam = params.get('state')

    if (code) {
      const verifier = getAndClearVerifier()
      if (!verifier) {
        setError(new Error('Missing PKCE verifier — login may have started in a different tab'))
        setIsLoading(false)
        return
      }

      let decodedState: Record<string, unknown> | undefined
      if (stateParam) {
        try {
          decodedState = JSON.parse(atob(stateParam))
        } catch {
          // state decode failed, continue without it
        }
      }

      // Validate state nonce for CSRF protection
      const storedNonce = getAndClearNonce()
      if (!decodedState?.nonce || decodedState.nonce !== storedNonce) {
        setError(new Error('Invalid state nonce — possible CSRF attack'))
        setIsLoading(false)
        return
      }

      client
        .exchangeCode(code, verifier, resolvedRedirectUri, clientId)
        .then(() => client.fetchSession())
        .then((session) => {
          setUser(session.user)
          setIsLoading(false)
          // Clean URL
          const cleanUrl = window.location.pathname
          window.history.replaceState({}, '', cleanUrl)
          if (onRedirectCallbackRef.current && session.user) {
            onRedirectCallbackRef.current({ user: session.user, state: decodedState })
          }
        })
        .catch((err) => {
          setError(err instanceof Error ? err : new Error(String(err)))
          setIsLoading(false)
        })
    } else {
      // No code — check for existing session
      client
        .fetchSession()
        .then((session) => {
          setUser(session.user)
          setIsLoading(false)
        })
        .catch((err) => {
          setError(err instanceof Error ? err : new Error(String(err)))
          setIsLoading(false)
        })
    }
  }, [client, resolvedRedirectUri, clientId])

  const signIn = useCallback(
    async (opts?: { organizationId?: string; returnTo?: string; state?: Record<string, unknown> }) => {
      const verifier = generateCodeVerifier()
      const challenge = await generateCodeChallenge(verifier)
      storeVerifier(verifier)

      const nonce = crypto.randomUUID()
      storeNonce(nonce)

      const statePayload = {
        ...opts?.state,
        ...(opts?.returnTo ? { returnTo: opts.returnTo } : {}),
        nonce,
      }
      const encodedState = btoa(JSON.stringify(statePayload))

      const params = new URLSearchParams({
        client_id: clientId,
        response_type: 'code',
        redirect_uri: resolvedRedirectUri,
        code_challenge: challenge,
        code_challenge_method: 'S256',
        scope: 'openid profile email',
        state: encodedState,
      })
      if (opts?.organizationId) params.set('organization_id', opts.organizationId)

      window.location.href = `${baseUrl}/oauth/authorize?${params}`
    },
    [clientId, baseUrl, resolvedRedirectUri],
  )

  const signOut = useCallback(
    async (opts?: { redirectTo?: string }) => {
      await client.logout()
      if (opts?.redirectTo) {
        window.location.replace(opts.redirectTo)
        return
      }
      setUser(null)
      queryClient.removeQueries({ queryKey: ['id.org.ai'] })
      setError(null)
    },
    [client, queryClient],
  )

  const getAccessToken = useCallback(async () => {
    if (accessToken) return accessToken
    return client.fetchWidgetToken()
  }, [client, accessToken])

  const contextValue = useMemo(
    () => ({
      user,
      isLoading,
      isAuthenticated: !!user,
      error,
      signIn,
      signOut,
      getAccessToken,
      accessToken,
      organizationId: user?.organizationId ?? null,
      permissions: user?.permissions ?? [],
    }),
    [user, isLoading, error, signIn, signOut, getAccessToken, accessToken],
  )

  return (
    <QueryClientProvider client={queryClient}>
      <IdConfigContext.Provider value={{ baseUrl }}>
        <IdAuthContext.Provider value={contextValue}>{children}</IdAuthContext.Provider>
      </IdConfigContext.Provider>
    </QueryClientProvider>
  )
}
