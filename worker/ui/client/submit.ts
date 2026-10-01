/**
 * Forms that leave id.org.ai (consent Allow, choosers, sign-in, step-up):
 * [data-js=submit]. On submit the connector goes `connecting` and the clicked
 * primary goes busy with its progressive label; the form then posts normally
 * and the browser follows the redirect (D7: no verdict before leaving).
 * Without JS the form simply posts.
 */
import { initSubmit } from './lib/submit'
import { enhance } from './lib/dom'

enhance<HTMLFormElement>('submit', initSubmit)
