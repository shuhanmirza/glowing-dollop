// OpenID Provider registry.
//
// Each entry describes one OP the wallet can mint a PK Token from. We reuse
// OpenPubkey's own public clients (from providers/*.go in
// github.com/openpubkey/openpubkey) so the demo can perform real logins without
// registering our own apps. These are public clients using PKCE; where the OP
// requires a client secret even for a public client (Google), OpenPubkey
// intentionally publishes it, so it holds no power.
//
// All of OpenPubkey's clients share the same loopback redirect URIs
// (localhost:{3000,10001,11110}/login-callback) and commit the ephemeral key in
// the OIDC `nonce`. We use port 10001 so the extension never collides with the
// Verifier demo backend (which serves its own /login-callback on 11110).
// Nothing listens on this port; the background worker intercepts the browser's
// navigation to it and reads the authorization code from the URL.

export const REDIRECT_URI = 'http://localhost:10001/login-callback'

const MS_TENANT = '9188040d-6c67-4c5b-b112-36a304b66dad'

// providers maps an OP id to its configuration. To add another OpenPubkey OP,
// add an entry here (and its token host to rules.json / host_permissions).
export const providers = {
  // Demo OP (Dex) run locally by this repo. A minimal, unmodified OIDC provider
  // for the abc.localhost namespace. Public PKCE client, no secret. Reachable at
  // http://op.localhost:5556 (see demo/op/README.md). Endpoints are the Dex
  // defaults; discovery on the issuer overrides them at runtime.
  dex: {
    id: 'dex',
    label: 'Demo OP (abc.localhost)',
    issuer: 'http://op.localhost:5556',
    clientId: 'byoid-demo',
    // Public client, no secret.
    scopes: 'openid profile email',
    authorizationEndpoint: 'http://op.localhost:5556/auth',
    tokenEndpoint: 'http://op.localhost:5556/token',
  },
  microsoft: {
    id: 'microsoft',
    label: 'Microsoft',
    issuer: `https://login.microsoftonline.com/${MS_TENANT}/v2.0`,
    clientId: '096ce0a3-5e72-4da8-9c86-12924b294a01',
    // Public client, no secret.
    scopes: 'openid profile email offline_access',
    // Force the account chooser so the user can add a different account, not
    // just re-consent the one already signed in. With `consent` alone Microsoft
    // goes straight to the current session's account.
    prompt: 'select_account',
    // Fallback endpoints if discovery fails.
    authorizationEndpoint: `https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/authorize`,
    tokenEndpoint: `https://login.microsoftonline.com/${MS_TENANT}/oauth2/v2.0/token`,
  },
  google: {
    id: 'google',
    label: 'Google',
    issuer: 'https://accounts.google.com',
    clientId: '206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com',
    // Google requires a client secret even for this public app; OpenPubkey
    // intentionally publishes it, so it holds no power.
    clientSecret: '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',
    scopes: 'openid profile email',
    // Show the account chooser and re-consent (consent keeps a refresh token
    // available for this offline-capable client).
    prompt: 'select_account consent',
    authorizationEndpoint: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenEndpoint: 'https://oauth2.googleapis.com/token',
  },
}

// providerList is the display order for the Add Identity picker. The demo OP is
// listed first so it is the obvious choice when running the local demo.
export const providerList = [providers.dex, providers.microsoft, providers.google]

// getProvider returns the OP config for an id, or throws if unknown.
export function getProvider(id) {
  const p = providers[id]
  if (!p) throw new Error(`unknown provider: ${id}`)
  return p
}
