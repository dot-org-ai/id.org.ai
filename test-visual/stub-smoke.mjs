#!/usr/bin/env node
/**
 * Smoke test for the WorkOS test seam: `wrangler dev` plus the local stub serve
 * /login and complete a sign-in end to end, without touching api.workos.com or
 * id.org.ai.
 *
 *   node test-visual/workos-stub.mjs &                       # :8788
 *   (cd worker && npx wrangler dev --local-upstream localhost:8787) &
 *   node test-visual/stub-smoke.mjs --base http://localhost:8787
 *
 * Every hop must stay on a loopback host: the script stops before following
 * any redirect elsewhere, so a misconfigured worker can never be walked into
 * production.
 */
const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => {
    if (a.startsWith('--')) acc.push([a.slice(2), all[i + 1] && !all[i + 1].startsWith('--') ? all[i + 1] : true])
    return acc
  }, []),
)
const BASE = String(args.base || 'http://localhost:8787').replace(/\/$/, '')
const LOOPBACK = new Set(['localhost', '127.0.0.1', '[::1]'])

function assertLocal(url) {
  const u = new URL(url)
  if (!LOOPBACK.has(u.hostname)) throw new Error(`refusing to follow a non-loopback hop: ${u.origin}${u.pathname}`)
  return u
}

const jar = new Map()
function remember(res) {
  for (const line of res.headers.getSetCookie?.() ?? []) {
    const [pair] = line.split(';')
    const eq = pair.indexOf('=')
    jar.set(pair.slice(0, eq).trim(), pair.slice(eq + 1))
  }
}
const cookieHeader = () => [...jar].map(([k, v]) => `${k}=${v}`).join('; ')

async function hop(url) {
  assertLocal(url)
  const res = await fetch(url, { redirect: 'manual', headers: { cookie: cookieHeader(), accept: 'text/html' } })
  remember(res)
  return res
}

async function main() {
  assertLocal(BASE)
  const page = await hop(`${BASE}/login`)
  const html = await page.text()
  if (page.status !== 200 || !html.includes('<html')) throw new Error(`/login answered ${page.status}`)
  console.log(`ok  GET /login → 200 HTML`)

  let res = await hop(`${BASE}/login?provider=GitHubOAuth&continue=/dash/profile`)
  for (let i = 0; i < 6 && res.status >= 300 && res.status < 400; i++) {
    const next = new URL(res.headers.get('location'), res.url).toString()
    console.log(`ok  ${res.status} → ${assertLocal(next).origin}${new URL(next).pathname}`)
    res = await hop(next)
  }
  if (!jar.has('auth')) throw new Error(`sign-in did not set the auth cookie (last status ${res.status})`)
  console.log('ok  signed in through the stub: auth cookie set')
}

main().catch((e) => {
  console.error(`FAIL ${e.message}`)
  process.exit(1)
})
