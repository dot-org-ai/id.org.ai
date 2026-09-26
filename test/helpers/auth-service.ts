/**
 * The AuthService entrypoint as a service-binding caller sees it: the class
 * the worker exports, constructed over the test worker's env. RPC methods are
 * reachable only this way (a binding), never through SELF.fetch.
 */
import { env, createExecutionContext } from 'cloudflare:test'
import { AuthService } from '../../worker/index'

export function authService(): AuthService {
  return new AuthService(createExecutionContext(), env as never)
}
