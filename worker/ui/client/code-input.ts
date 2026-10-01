/**
 * Code boxes (components.md#code-input): typing advances, Backspace on an
 * empty box goes back, arrows move, and pasting a whole code fills every box
 * ("WDJB-MJHT", "wdjbmjht" and "WDJB MJHT" all work; device codes uppercase).
 * Never auto-submits. Focuses the first empty box on load, except when frozen.
 */
import { initCodeInput } from './lib/code-input'
import { enhance } from './lib/dom'

enhance('code-input', initCodeInput)
