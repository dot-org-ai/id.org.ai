import { provision } from '../claim/client.js'
import type { ProvisionStorage } from './provision-storage.js'
import { cleanText } from './untrusted.js'

export interface ProvisionCommandOptions {
  baseUrl: string
  json: boolean
  storage: ProvisionStorage
}

export async function provisionCommand(opts: ProvisionCommandOptions): Promise<void> {
  try {
    const result = await provision(opts.baseUrl)

    await opts.storage.setProvisionData({
      tenantId: result.tenantId,
      sessionToken: result.sessionToken,
      claimToken: result.claimToken,
      createdAt: Date.now(),
    })

    if (opts.json) {
      console.log(JSON.stringify(result, null, 2))
      return
    }

    console.log('')
    console.log('  Anonymous sandbox created')
    console.log('')
    console.log(`  Tenant:      ${cleanText(result.tenantId)}`)
    console.log(`  Claim Token: ${cleanText(result.claimToken)}`)
    console.log(`  Level:       ${cleanText(String(result.level))}`)
    console.log(`  Expires:     ${cleanText(String(result.limits?.ttlHours))} hours`)
    console.log('')
    console.log('  Next step: id.org.ai claim')
    console.log('')
  } catch (err) {
    console.error(`Provision failed: ${cleanText(err instanceof Error ? err.message : err)}`)
    console.error('Try again, or check https://id.org.ai for status.')
    process.exit(1)
  }
}
