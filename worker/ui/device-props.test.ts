/**
 * The device line on 4b and 4d (backend.md#b3): "macOS · Miami, FL ·
 * requested 1 min ago", unknown parts left out with their separators, and a
 * place always shown (phase 6 review S5, S8).
 */
import { describe, expect, it } from 'vitest'
import { deviceMetaLine, deviceWhere } from './device-props'

const NOW = 1_700_000_000_000

describe('deviceWhere / deviceMetaLine', () => {
  it('names the OS and the city and region, then how long ago', () => {
    const meta = { os: 'macOS', city: 'Miami', region: 'FL', country: 'US', requestedAt: NOW - 61_000 }
    expect(deviceWhere(meta)).toBe('macOS · Miami, FL')
    expect(deviceMetaLine(meta, NOW)).toBe('macOS · Miami, FL · requested 1 min ago')
    expect(deviceMetaLine({ ...meta, requestedAt: NOW - 7 * 60_000 }, NOW)).toBe('macOS · Miami, FL · requested 7 min ago')
    expect(deviceMetaLine({ ...meta, requestedAt: NOW - 20_000 }, NOW)).toBe('macOS · Miami, FL · requested just now')
  })

  it('leaves out what isn’t known, with its separator, but always shows a place', () => {
    expect(deviceWhere({ city: 'Miami', requestedAt: NOW })).toBe('Miami')
    expect(deviceWhere({ os: 'Linux', country: 'DE', requestedAt: NOW })).toBe('Linux · DE')
    expect(deviceWhere({ os: 'Linux', requestedAt: NOW })).toBe('Linux · location unknown')
    expect(deviceMetaLine({ requestedAt: NOW }, NOW)).toBe('location unknown · requested just now')
  })
})
