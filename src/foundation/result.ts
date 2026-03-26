export type Result<T, E> = { success: true; data: T } | { success: false; error: E }

export function Ok<T>(data: T): Result<T, never> {
  return { success: true, data }
}

export function Err<E>(error: E): Result<never, E> {
  return { success: false, error }
}

export function isOk<T, E>(result: Result<T, E>): result is { success: true; data: T } {
  return result.success === true
}

export function isErr<T, E>(result: Result<T, E>): result is { success: false; error: E } {
  return result.success === false
}

export function map<T, U, E>(result: Result<T, E>, fn: (value: T) => U): Result<U, E> {
  if (isOk(result)) return Ok(fn(result.data))
  return result
}

export function flatMap<T, U, E1, E2>(result: Result<T, E1>, fn: (value: T) => Result<U, E2>): Result<U, E1 | E2> {
  if (isOk(result)) return fn(result.data)
  return result
}

export function unwrapOr<T, E>(result: Result<T, E>, fallback: T): T {
  if (isOk(result)) return result.data
  return fallback
}
