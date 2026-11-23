/** Money and list wording for the agent setup screens (HANDOFF.md section 6, Copy). */

/**
 * The drawings' per-unit wording as these screens write it (owner direction, 2026-11-23):
 * "$299 a month" → "$299/month", "$0.0025 a call" → "$0.0025/call", and a plan's price
 * note "a month + data fees" → "/month + data fees". HANDOFF.md section 6 says "a month";
 * this overrides it. The checks that compare a page with its drawing apply this to the
 * drawing first. Counts stay as written ("1,000 calls a month").
 */
export function slashUnits(text: string): string {
  return text.replace(/(?<=[\d\]]) a (month|call)/g, '/$1').replace(/^a month \+/, '/month +')
}

/** 50000 → "$500", 29900 → "$299", 100 → "$1", 4120 → "$41.20". Whole dollars drop the cents. */
export function usd(cents: number): string {
  const whole = cents % 100 === 0
  return '$' + (cents / 100).toLocaleString('en-US', { minimumFractionDigits: whole ? 0 : 2, maximumFractionDigits: whole ? 0 : 2 })
}

/** 29900 → "$299.00": every charge and total shows its cents. */
export function usdExact(cents: number): string {
  return '$' + (cents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })
}

/** "$299/month", never "/mo". */
export function perMonth(cents: number): string {
  return `${usd(cents)}/month`
}

/** ["a", "b", "c"] → "a, b and c". */
export function listAnd(items: string[]): string {
  if (items.length <= 1) return items.join('')
  return `${items.slice(0, -1).join(', ')} and ${items[items.length - 1]}`
}

/** "Emails at $100, $500, $1,000, $2,000 and $5,000." */
export function alertsSentence(marks: number[]): string {
  return `Emails at ${listAnd(marks.map(usd))}.`
}

/** The spend limit's option label: null is "No limit". */
export function limitLabel(cents: number | null): string {
  return cents === null ? 'No limit' : perMonth(cents)
}

/** "2026-11-22T19:14:02Z" → "2:14 PM" in the given zone (the person's, from their session). */
export function clock(iso: string, timeZone = 'America/New_York'): string {
  return new Date(iso).toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', timeZone })
}
