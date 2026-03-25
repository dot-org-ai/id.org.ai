'use client'

import { useContext } from 'react'
import { IdAuthContext } from '../context'
import type { AuthContext } from '../types'

export function useAuth(): AuthContext {
  const context = useContext(IdAuthContext)
  if (!context) {
    throw new Error('useAuth must be used within an <IdProvider>')
  }
  return context
}
