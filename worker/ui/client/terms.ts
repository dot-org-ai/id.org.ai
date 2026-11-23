/** The terms line (19b, 24b): see lib/terms.ts. */
import { enhance } from './lib/dom'
import { initTerms } from './lib/terms'

enhance<HTMLInputElement>('terms', (el) => initTerms(el))
