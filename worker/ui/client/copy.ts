/**
 * Copy buttons (components.md#copy-button): [data-js=copy][data-value].
 * Unhides itself (hidden without JS), writes the clipboard, shows the green
 * check and announces "Copied" for 1.5s; a second click restarts the timer.
 * Never resets a server-rendered copied state; frozen pages never time out.
 */
import { initCopy } from './lib/copy'
import { enhance } from './lib/dom'

enhance<HTMLButtonElement>('copy', (el) => initCopy(el))
