import type { TileContent } from '../components'
import type { Product } from './types'

/**
 * A product's tile: its own logo when it sends one, its letters otherwise. The letters also
 * stand in if the logo is refused (not https) or fails to load (logo.ts swaps them in).
 */
export function productTile(product: Pick<Product, 'tile' | 'logo_url'>): TileContent {
  return product.logo_url ? { kind: 'logo', src: product.logo_url, monogram: product.tile } : { kind: 'monogram', text: product.tile }
}
