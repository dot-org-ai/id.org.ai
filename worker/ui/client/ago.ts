/** The setup page's header status: see lib/ago.ts. */
import { initAgo } from './lib/ago'
import { enhance } from './lib/dom'

enhance('ago', (el) => initAgo(el))
