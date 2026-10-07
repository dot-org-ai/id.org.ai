/**
 * Fixed destinations shown on every auth page.
 * The Privacy, Terms and Status pages don't exist yet on id.org.ai; these are
 * placeholders the owners replace (docs/product-update/PROGRESS.md, owner steps).
 */
export const LINKS = {
  home: '/',
  privacy: '/privacy',
  terms: '/terms',
  status: '/status',
} as const
