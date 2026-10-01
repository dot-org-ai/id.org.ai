/**
 * 4b · the device-confirm state machine (spec/motion.md#device-confirm-4b-the-reference-state-machine).
 *
 *   idle ─Confirm→ connecting ─OK→ done ─2150ms→ signed
 *                      └─error→ broken ─1820ms→ error content
 *   idle ─Cancel→ cancelling (broken, both disabled) ─1820ms and deny OK→ cancelled
 *                                                     └─deny failed→ error content
 *
 * The server renders the signed, cancelled and error bodies and feet into
 * <template data-state> elements; this swaps them into [data-region]. Without
 * JS the form posts and the server answers with 4d or the cancelled page.
 */
import { initDeviceConfirm } from './lib/device-confirm'
import { enhance, isFrozen } from './lib/dom'

enhance<HTMLFormElement>('device-confirm', (form) => {
  if (!isFrozen()) initDeviceConfirm(form)
})
