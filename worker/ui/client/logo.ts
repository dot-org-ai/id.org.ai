/**
 * App logos (logos.md): a client's logo_uri that fails to load falls back to
 * the monogram. [data-js=logo] wraps the <img> and carries data-monogram.
 */
import { initLogo } from './lib/logo'
import { enhance } from './lib/dom'

enhance('logo', initLogo)
