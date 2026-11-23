/** Disclosure buttons (plan cards, spend alerts): see lib/disclose.ts. */
import { initDisclose } from './lib/disclose'
import { enhance } from './lib/dom'

enhance<HTMLButtonElement>('disclose', (el) => initDisclose(el))
