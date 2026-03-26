import { describe, it, expect } from 'vitest'
import { Ok, Err, isOk, isErr, map, flatMap, unwrapOr } from '../src/foundation/result'

describe('Ok', () => {
  it('creates { success: true, data: value }', () => {
    const result = Ok(42)
    expect(result).toEqual({ success: true, data: 42 })
  })

  it('works with complex types (objects)', () => {
    const value = { name: 'Alice', age: 30 }
    const result = Ok(value)
    expect(result).toEqual({ success: true, data: value })
  })

  it('works with undefined for void-returning services', () => {
    const result = Ok(undefined)
    expect(result).toEqual({ success: true, data: undefined })
  })
})

describe('Err', () => {
  it('creates { success: false, error: value }', () => {
    const result = Err('something went wrong')
    expect(result).toEqual({ success: false, error: 'something went wrong' })
  })

  it('works with error objects', () => {
    const error = new Error('failure')
    const result = Err(error)
    expect(result).toEqual({ success: false, error })
  })
})

describe('isOk', () => {
  it('returns true for Ok', () => {
    expect(isOk(Ok(1))).toBe(true)
  })

  it('returns false for Err', () => {
    expect(isOk(Err('e'))).toBe(false)
  })

  it('narrows the type — access .data in if block', () => {
    const result = Ok('hello') as ReturnType<typeof Ok<string>> | ReturnType<typeof Err<string>>
    if (isOk(result)) {
      // TypeScript should allow this without error
      const _data: string = result.data
      expect(_data).toBe('hello')
    }
  })
})

describe('isErr', () => {
  it('returns true for Err', () => {
    expect(isErr(Err('e'))).toBe(true)
  })

  it('returns false for Ok', () => {
    expect(isErr(Ok(1))).toBe(false)
  })
})

describe('map', () => {
  it('transforms Ok value', () => {
    const result = map(Ok(2), (n) => n * 3)
    expect(result).toEqual({ success: true, data: 6 })
  })

  it('passes Err through without calling fn', () => {
    const fn = (n: number) => n * 3
    const result = map(Err('error'), fn)
    expect(result).toEqual({ success: false, error: 'error' })
  })

  it('works over void Ok', () => {
    const result = map(Ok(undefined), () => 'done')
    expect(result).toEqual({ success: true, data: 'done' })
  })
})

describe('flatMap', () => {
  it('chains Ok results', () => {
    const result = flatMap(Ok(5), (n) => Ok(n * 2))
    expect(result).toEqual({ success: true, data: 10 })
  })

  it('short-circuits on first Err input', () => {
    const fn = (n: number) => Ok(n * 2)
    const result = flatMap(Err('first error'), fn)
    expect(result).toEqual({ success: false, error: 'first error' })
  })

  it('returns Err from mapping function', () => {
    const result = flatMap(Ok(5), (_n) => Err('mapping failed'))
    expect(result).toEqual({ success: false, error: 'mapping failed' })
  })
})

describe('unwrapOr', () => {
  it('returns value for Ok', () => {
    expect(unwrapOr(Ok(42), 0)).toBe(42)
  })

  it('returns fallback for Err', () => {
    expect(unwrapOr(Err('e'), 99)).toBe(99)
  })
})
