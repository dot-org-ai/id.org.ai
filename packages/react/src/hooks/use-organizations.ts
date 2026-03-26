'use client'

import { useCallback, useContext, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { IdAuthContext, IdConfigContext } from '../context'
import { createIdClient } from '../client'
import type { OrganizationsContext } from '../types'

export function useOrganizations(): OrganizationsContext {
  const authContext = useContext(IdAuthContext)
  const config = useContext(IdConfigContext)

  if (!authContext || !config) {
    throw new Error('useOrganizations must be used within an <IdProvider>')
  }

  const client = useMemo(() => createIdClient(config.baseUrl), [config.baseUrl])
  const qc = useQueryClient()

  const {
    data: organizations = [],
    isLoading,
    error,
  } = useQuery({
    queryKey: ['id.org.ai', 'organizations'],
    queryFn: () => client.fetchOrganizations(),
    enabled: authContext.isAuthenticated,
    staleTime: 5 * 60 * 1000, // 5 minutes — orgs change rarely
  })

  const switchOrganization = useCallback(
    async (orgId: string) => {
      await client.switchOrganization(orgId)
      // Invalidate access token (org-scoped)
      qc.removeQueries({ queryKey: ['id.org.ai', 'accessToken'] })
      // Refresh session to update useAuth() state
      window.dispatchEvent(new CustomEvent('id.org.ai:session-refresh'))
    },
    [client, qc],
  )

  const createMutation = useMutation({
    mutationFn: (name: string) => client.createOrganization(name),
    onSuccess: async (org) => {
      // Refetch org list
      await qc.invalidateQueries({ queryKey: ['id.org.ai', 'organizations'] })
      // Auto-switch to new org
      await switchOrganization(org.id)
    },
  })

  const createOrganization = useCallback((name: string) => createMutation.mutateAsync(name), [createMutation])

  return {
    organizations,
    isLoading,
    error: error ?? null,
    switchOrganization,
    createOrganization,
    isCreating: createMutation.isPending,
  }
}
