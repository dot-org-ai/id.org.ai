/**
 * Hashed static asset paths, written by scripts/build-ui.mjs into assets.json.
 * `assetUrl('ui.css')` → `/auth/ui.<hash>.css`; `assetUrl('copy.js')` → `/auth/copy.<hash>.js`.
 */
import assets from './assets.json'

export type AssetName = keyof typeof assets
export type ClientScript = Exclude<AssetName, 'ui.css'>

export const FONT_PRELOAD = '/fonts/geist/Geist-Variable.woff2'

export function assetUrl(name: AssetName): string {
  return assets[name]
}
