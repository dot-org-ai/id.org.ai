/**
 * 5d · live claim-by-commit status: polls data-status-url every 5s and maps
 * unclaimed → waiting, pending → pending on a branch, claimed → claimed. The
 * status list updates in place and the connector goes connecting → done → ok.
 * Frozen pages never poll.
 */
import { initClaimStatus } from './lib/claim-status'
import { enhance, isFrozen } from './lib/dom'

enhance('claim-status', (el) => {
  if (!isFrozen()) initClaimStatus(el)
})
