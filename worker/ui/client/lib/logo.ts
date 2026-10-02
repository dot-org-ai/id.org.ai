/**
 * App logos (logos.md): a client's logo_uri that fails to load falls back to
 * the monogram. [data-js=logo] wraps the <img> and carries data-monogram.
 */

export function initLogo(tile: HTMLElement): void {
  const img = tile.querySelector('img')
  if (!img) return
  const fallback = () => {
    tile.textContent = tile.dataset.monogram ?? ''
  }
  if (img.complete && img.naturalWidth === 0) fallback()
  else img.addEventListener('error', fallback, { once: true })
}

