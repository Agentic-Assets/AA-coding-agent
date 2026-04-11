import { type NextRequest } from 'next/server'
import { cookies } from 'next/headers'
import { generateState } from 'arctic'
import { isRelativeUrl } from '@/lib/utils/is-relative-url'
import { getSessionFromReq } from '@/lib/session/server'
import { getProductionCallbackUrl, signState } from '@/lib/auth/github-oauth-state'

export async function GET(req: NextRequest): Promise<Response> {
  // Check if user is already authenticated with Vercel
  let session
  try {
    session = await getSessionFromReq(req)
  } catch {
    // Session retrieval failed - proceed as new sign-in
    session = undefined
  }

  const clientId = process.env.NEXT_PUBLIC_GITHUB_CLIENT_ID
  // On Vercel preview deployments, GitHub won't accept our per-commit
  // callback URL (it only trusts the single registered production URL).
  // Route `redirect_uri` through production; the production callback
  // verifies a signed state and forwards the `code` back here.
  const productionCallback = getProductionCallbackUrl('/api/auth/github/callback')
  const redirectUri = productionCallback ?? `${req.nextUrl.origin}/api/auth/github/callback`

  if (!clientId) {
    return Response.redirect(new URL('/?error=github_not_configured', req.url))
  }

  const state = generateState()
  const store = await cookies()
  let redirectTo = isRelativeUrl(req.nextUrl.searchParams.get('next') ?? '/')
    ? (req.nextUrl.searchParams.get('next') ?? '/')
    : '/'

  // If user is already authenticated with Vercel, treat this as a "Connect GitHub" flow
  // Otherwise, treat it as a "Sign in with GitHub" flow
  const isSignInFlow = !session?.user
  const authMode = isSignInFlow ? 'signin' : 'connect'

  // Add a query parameter to show a toast message after redirect
  if (!isSignInFlow) {
    const redirectUrl = new URL(redirectTo, req.nextUrl.origin)
    redirectUrl.searchParams.set('github_connected', 'true')
    redirectTo = redirectUrl.pathname + redirectUrl.search
  }

  // Store state and redirect URL
  const cookiesToSet: [string, string][] = [
    [`github_auth_redirect_to`, redirectTo],
    [`github_auth_state`, state],
    [`github_auth_mode`, authMode],
  ]

  // If connecting (user already signed in), store their user ID
  if (!isSignInFlow && session?.user?.id) {
    cookiesToSet.push([`github_oauth_user_id`, session.user.id])
  }

  for (const [key, value] of cookiesToSet) {
    store.set(key, value, {
      path: '/',
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 60 * 10, // 10 minutes
      sameSite: 'lax',
    })
  }

  // When proxying through production, GitHub receives a signed state that
  // encodes the preview origin. The production callback verifies the
  // signature and forwards the `code` back to that origin, which then reads
  // its own `github_auth_state` cookie (containing the original `state`)
  // to complete CSRF validation. If signing is unavailable (missing
  // JWE_SECRET) we fall back to the raw state and the flow behaves as if
  // no proxy were in use.
  const outboundState = productionCallback ? (signState({ state, origin: req.nextUrl.origin }) ?? state) : state

  // Build GitHub authorization URL
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'repo,read:user,user:email',
    state: outboundState,
  })

  const url = `https://github.com/login/oauth/authorize?${params.toString()}`

  // Redirect directly to GitHub
  return Response.redirect(url)
}
