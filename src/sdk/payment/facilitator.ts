/**
 * FacilitatorClient — abstraction over an x402 / MPP facilitator service.
 *
 * Both x402 and MPP delegate the chain-side work (signature verification,
 * broadcast, settlement) to an optional facilitator. The broker calls
 * `verify()` before fulfilment and `settle()` after, so the rail adapters
 * stay free of chain clients (no viem/ethers in the worker bundle).
 *
 * Wire format follows the x402 v2 / MPP IETF draft conventions but is
 * normalised here: rail adapters translate their protocol-specific shapes
 * into the common request shape below before calling the facilitator.
 */

/** Verification request — what the rail adapter sends to /verify. */
export interface FacilitatorVerifyRequest {
  protocol: 'x402' | 'mpp'
  method: string
  /** CAIP-2 chain id, when the rail is on-chain. */
  network?: string
  /**
   * The accepted requirement, in the protocol's own shape. The facilitator
   * needs this to know what was offered (amount, asset, payTo, …).
   */
  accepted: Record<string, unknown>
  /**
   * The payment proof the client returned, in the protocol's own shape
   * (e.g. EIP-3009 authorization for x402, MPP `Authorization: Payment`
   * payload for MPP).
   */
  payload: Record<string, unknown>
}

export interface FacilitatorVerifyResponse {
  valid: boolean
  /** Failure reason when `valid === false`. */
  reason?: string
  /** The payer the facilitator inferred from the proof, when known. */
  payer?: string
}

/** Settlement request — what the rail adapter sends to /settle. */
export interface FacilitatorSettleRequest extends FacilitatorVerifyRequest {}

export interface FacilitatorSettleResponse {
  success: boolean
  /** Transaction hash / voucher id / charge id. */
  transaction?: string
  /** Payer when known. */
  payer?: string
  /** Failure reason when `success === false`. */
  errorReason?: string
}

export interface FacilitatorClient {
  verify(req: FacilitatorVerifyRequest): Promise<FacilitatorVerifyResponse>
  settle(req: FacilitatorSettleRequest): Promise<FacilitatorSettleResponse>
}

/**
 * Concrete fetch-based implementation. Posts JSON to `<baseUrl>/verify` and
 * `<baseUrl>/settle`. Suitable for Cloudflare Workers (no Node deps).
 *
 * Tests should pass a fake satisfying the `FacilitatorClient` shape rather
 * than mocking fetch.
 */
export class HttpFacilitatorClient implements FacilitatorClient {
  constructor(
    private readonly baseUrl: string,
    private readonly headers: Record<string, string> = {},
  ) {}

  async verify(req: FacilitatorVerifyRequest): Promise<FacilitatorVerifyResponse> {
    return this.post<FacilitatorVerifyResponse>('/verify', req)
  }

  async settle(req: FacilitatorSettleRequest): Promise<FacilitatorSettleResponse> {
    return this.post<FacilitatorSettleResponse>('/settle', req)
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = this.baseUrl.endsWith('/')
      ? `${this.baseUrl.slice(0, -1)}${path}`
      : `${this.baseUrl}${path}`
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...this.headers },
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      throw new Error(`facilitator ${path} → ${res.status} ${res.statusText}`)
    }
    return (await res.json()) as T
  }
}
