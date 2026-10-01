#!/usr/bin/env node
/**
 * pnpm dev:worker: `wrangler dev` for the auth worker, on PORT (default 8787).
 *
 * --local-upstream keeps the request host as the local one. Without it,
 * wrangler presents the first route's host (oauth.do) to the worker, so /login
 * would send WorkOS id.org.ai's production callback instead of the local one.
 */
import { spawnSync } from 'node:child_process'

const port = process.env.PORT || '8787'
const r = spawnSync('npx', ['wrangler', 'dev', '--port', port, '--ip', '127.0.0.1', '--local-upstream', `localhost:${port}`, ...process.argv.slice(2)], {
  cwd: new URL('../worker/', import.meta.url).pathname,
  stdio: 'inherit',
})
process.exit(r.status ?? 1)
