'use client'

import { createContext } from 'react'
import type { AuthContext } from './types'

export const IdAuthContext = createContext<AuthContext | null>(null)
export const IdConfigContext = createContext<{ baseUrl: string } | null>(null)
