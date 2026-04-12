import { createHmac, timingSafeEqual } from 'node:crypto'

// Signed OAuth state for preview-deployment proxy flow.
//
// Problem: GitHub OAuth Apps allow exactly one callback URL. Vercel preview
// deployments have per-commit hostnames, so previews cannot register their
// own callback. Solution: previews send the production callback URL to
// GitHub, but encode their own origin into a signed `state` param. The
// production callback verifies the signature and 302-forwards the `code`
// back to the originating preview, which completes the token exchange and
// sets its own session cookie. See app/api/auth/github/callback/route.ts.

const VERSION = 'v1'

type StatePayload = {
  state: string
  origin: string
}

function base64urlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function base64urlDecode(str: string): Buffer {
  const pad = str.length % 4 === 0 ? '' : '='.repeat(4 - (str.length % 4))
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/') + pad, 'base64')
}

function getSecret(): string | null {
  return process.env.JWE_SECRET ?? null
}

export function signState(payload: StatePayload): string | null {
  const secret = getSecret()
  if (!secret) return null

  const body = base64urlEncode(Buffer.from(JSON.stringify(payload), 'utf8'))
  const sig = base64urlEncode(createHmac('sha256', secret).update(`${VERSION}.${body}`).digest())
  return `${VERSION}.${body}.${sig}`
}

export function verifyState(signed: string): StatePayload | null {
  const secret = getSecret()
  if (!secret) return null

  const parts = signed.split('.')
  if (parts.length !== 3) return null
  const [version, body, sig] = parts
  if (version !== VERSION) return null

  const expected = createHmac('sha256', secret).update(`${version}.${body}`).digest()
  let provided: Buffer
  try {
    provided = base64urlDecode(sig)
  } catch {
    return null
  }
  if (provided.length !== expected.length) return null
  if (!timingSafeEqual(provided, expected)) return null

  try {
    const parsed = JSON.parse(base64urlDecode(body).toString('utf8')) as unknown
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'state' in parsed &&
      'origin' in parsed &&
      typeof (parsed as StatePayload).state === 'string' &&
      typeof (parsed as StatePayload).origin === 'string'
    ) {
      return parsed as StatePayload
    }
    return null
  } catch {
    return null
  }
}

// Returns the production callback URL if the current deployment is a Vercel
// preview that must proxy through production, else null.
export function getProductionCallbackUrl(path: string): string | null {
  if (process.env.VERCEL_ENV !== 'preview') return null
  const host = process.env.VERCEL_PROJECT_PRODUCTION_URL
  if (!host) return null
  return `https://${host}${path}`
}

// Open-redirect guard for the production proxy step. The HMAC signature is
// the primary defense (only our own code can sign state), but we additionally
// require the target origin to be either the canonical production host or a
// *.vercel.app subdomain to limit blast radius if JWE_SECRET ever leaks.
export function isAllowedProxyOrigin(origin: string): boolean {
  let parsed: URL
  try {
    parsed = new URL(origin)
  } catch {
    return false
  }
  if (parsed.protocol !== 'https:') return false
  const host = parsed.hostname
  const productionHost = process.env.VERCEL_PROJECT_PRODUCTION_URL ?? ''
  if (productionHost && host === productionHost) return true
  if (host.endsWith('.vercel.app')) return true
  return false
}
