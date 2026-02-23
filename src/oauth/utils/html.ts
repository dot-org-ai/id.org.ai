/**
 * HTML generation utilities for OAuth server
 */

/**
 * Redirect to the client with an OAuth error
 */
export function redirectWithError(redirectUri: string, error: string, description?: string, state?: string): Response {
  try {
    const url = new URL(redirectUri)
    url.searchParams.set('error', error)
    if (description) {
      url.searchParams.set('error_description', description)
    }
    if (state) {
      url.searchParams.set('state', state)
    }
    return Response.redirect(url.toString(), 302)
  } catch {
    // If redirect_uri is malformed, return a JSON error response instead of redirecting
    return new Response(
      JSON.stringify({
        error,
        error_description: description || 'Invalid redirect_uri',
      }),
      {
        status: 400,
        headers: { 'Content-Type': 'application/json' },
      },
    )
  }
}
