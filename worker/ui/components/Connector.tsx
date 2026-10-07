import type { JSX } from 'hono/jsx/jsx-runtime'
import { AppTile, type TileContent } from './AppTile'

export type ConnectorState = 'idle' | 'connecting' | 'done' | 'broken' | 'ok' | 'fail'

/** The verdict check: drawn with pathLength=1 so idcheck can draw it (motion.md#geometry-card-scale). */
function Check(): JSX.Element {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" aria-hidden="true" class="id-conn__check">
      <path d="M5 12.5 9.5 17 19 7" pathLength="1" stroke="currentColor" stroke-width="2.25" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="1" />
    </svg>
  )
}

function X(): JSX.Element {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" class="id-icon">
      <path d="M18 6 6 18" />
      <path d="m6 6 12 12" />
    </svg>
  )
}

/**
 * The connector (motion.md): two tiles joined by five dots. The state lives in
 * data-state, so connector.ts switches states by changing one attribute; every
 * state's markup is the same (the middle dot, both verdict glyphs and the ring
 * are always present and shown by CSS). Decorative: the page text announces.
 */
export function Connector({ left, right, state = 'idle' }: { left: TileContent; right: TileContent; state?: ConnectorState }): JSX.Element {
  return (
    <div class="id-conn" data-state={state} data-js="connector" aria-hidden="true">
      <div class="id-tile-wrap">
        <AppTile content={left} />
      </div>
      <div class="id-conn__wire">
        <div class="id-conn__dots">
          <span class="id-conn__dot id-conn__dot--0"></span>
          <span class="id-conn__dot id-conn__dot--1"></span>
          <span class="id-conn__mid">
            <span class="id-conn__morph">
              <span class="id-conn__dot id-conn__dot--2"></span>
            </span>
            <span class="id-conn__glyph id-conn__glyph--check">
              <Check />
            </span>
            <span class="id-conn__glyph id-conn__glyph--x">
              <span class="id-conn__x">
                <X />
              </span>
            </span>
          </span>
          <span class="id-conn__dot id-conn__dot--3"></span>
          <span class="id-conn__dot id-conn__dot--4"></span>
        </div>
      </div>
      <div class="id-tile-wrap">
        <AppTile content={right} />
        <span class="id-conn__ring"></span>
      </div>
    </div>
  )
}

/** A single tile in the head (1d first run: id.org.ai only, no connector). */
export function SingleTile({ content }: { content: TileContent }): JSX.Element {
  return (
    <div class="id-tile-wrap">
      <AppTile content={content} />
    </div>
  )
}
