// OIDC authorization-code + PKCE helpers.
//
// The extension drives the OIDC flow itself (the crypto for the PK Token lives
// in WASM; this module only handles the OAuth requests). Each function takes an
// OP config from the provider registry (see config.js), so the flow is
// provider-agnostic. All OpenPubkey clients are public clients using PKCE;
// where an OP requires a client secret even for a public client (Google), the
// config carries the intentionally-published secret.

import { REDIRECT_URI } from './config.js'

// base64url without padding.
function b64url(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

// randomString returns a base64url-encoded random string from n bytes.
function randomString(n) {
  const b = new Uint8Array(n)
  crypto.getRandomValues(b)
  return b64url(b)
}

// pkceChallenge computes the S256 challenge for a verifier.
async function pkceChallenge(verifier) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))
  return b64url(new Uint8Array(digest))
}

// discoverEndpoints fetches the OP's OpenID configuration, falling back to the
// endpoints in the provider config if discovery fails.
export async function discoverEndpoints(provider) {
  try {
    const res = await fetch(provider.issuer + '/.well-known/openid-configuration')
    if (res.ok) {
      const doc = await res.json()
      if (doc.authorization_endpoint && doc.token_endpoint) {
        return {
          authorizationEndpoint: doc.authorization_endpoint,
          tokenEndpoint: doc.token_endpoint,
        }
      }
    }
  } catch (e) {
    // fall through to defaults
  }
  return {
    authorizationEndpoint: provider.authorizationEndpoint,
    tokenEndpoint: provider.tokenEndpoint,
  }
}

// beginAuth builds the authorization request for the given nonce (the CIC hash
// from WASM). Returns the URL to open plus the state and PKCE verifier the
// caller must keep for the token exchange.
export async function beginAuth(provider, nonce) {
  const state = randomString(24)
  const codeVerifier = randomString(48)
  const codeChallenge = await pkceChallenge(codeVerifier)
  const { authorizationEndpoint, tokenEndpoint } = await discoverEndpoints(provider)

  const params = new URLSearchParams({
    client_id: provider.clientId,
    response_type: 'code',
    redirect_uri: REDIRECT_URI,
    scope: provider.scopes,
    response_mode: 'query',
    nonce,
    state,
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
  })
  // Per-provider prompt: force the account chooser so users can add a different
  // account instead of being sent straight to the one already signed in. Only
  // added when the provider declares it — some OPs (e.g. Dex) do not support
  // `select_account` and should be sent no prompt at all.
  if (provider.prompt) {
    params.set('prompt', provider.prompt)
  }
  return {
    url: `${authorizationEndpoint}?${params.toString()}`,
    state,
    codeVerifier,
    tokenEndpoint,
  }
}

// exchangeCode swaps an authorization code for tokens using PKCE. Returns the
// parsed token response including id_token.
//
// OpenPubkey's clients are native/public clients. A browser fetch attaches an
// `Origin: chrome-extension://...` header, and some OPs (Microsoft) reject
// cross-origin token redemption for non-SPA clients (AADSTS90023). A
// declarativeNetRequest rule (rules.json) strips the Origin header from the
// token requests so they look like native redemptions, exactly as OpenPubkey's
// own (server-side) exchange does. Our host_permissions for the OP token hosts
// let us read the responses regardless of CORS.
export async function exchangeCode(provider, tokenEndpoint, code, codeVerifier) {
  const body = new URLSearchParams({
    client_id: provider.clientId,
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT_URI,
    code_verifier: codeVerifier,
    scope: provider.scopes,
  })
  // Some OPs (Google) require a client secret even for a public client.
  if (provider.clientSecret) {
    body.set('client_secret', provider.clientSecret)
  }
  const res = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw new Error(data.error_description || data.error || `token endpoint returned ${res.status}`)
  }
  if (!data.id_token) {
    throw new Error('token response did not include an id_token')
  }
  return data
}

// decodeJwtPayload decodes (without verifying) a JWT's payload claims. The PK
// Token's signature is what actually matters; this is only used to display the
// email and expiry in the wallet.
export function decodeJwtPayload(jwt) {
  const part = jwt.split('.')[1]
  if (!part) throw new Error('malformed JWT')
  const json = atob(part.replace(/-/g, '+').replace(/_/g, '/'))
  return JSON.parse(json)
}
