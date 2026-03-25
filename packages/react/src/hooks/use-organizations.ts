'use client'

import { useState, useEffect, useCallback, useContext, useMemo } from 'react'
import { IdAuthContext, IdConfigContext } from '../context'
import { createIdClient } from '../client'
import type { Organization, OrganizationsContext } from '../types'

export function useOrganizations(): OrganizationsContext {
  const authContext = useContext(IdAuthContext)
  const config = useContext(IdConfigContext)

  if (!authContext || !config) {
    throw new Error('useOrganizations must be used within an <IdProvider>')
  }

  const [organizations, setOrganizations] = useState<Organization[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<Error | null>(null)

  const client = useMemo(() => createIdClient(config.baseUrl), [config.baseUrl])

  useEffect(() => {
    if (!authContext.isAuthenticated) return

    setIsLoading(true)
    client
      .fetchOrganizations()
      .then((orgs) => {
        setOrganizations(orgs)
        setIsLoading(false)
      })
      .catch((err) => {
        setError(err instanceof Error ? err : new Error(String(err)))
        setIsLoading(false)
      })
  }, [authContext.isAuthenticated, client])

  const switchOrganization = useCallback(
    async (orgId: string) => {
      await client.switchOrganization(orgId)
      // Cookie updated server-side — re-fetch session to update useAuth() state
      // We dispatch a custom event that IdProvider listens for
      window.dispatchEvent(new CustomEvent('id.org.ai:session-refresh'))
    },
    [client],
  )

  return { organizations, isLoading, error, switchOrganization }
}
