// Background service worker: captures the OIDC redirect.
//
// We reuse OpenPubkey's public client, whose redirect URI is a loopback address
// (http://localhost:10001/login-callback) that nothing actually serves. After
// the user authenticates, the browser tries to navigate the login tab to that
// address. We intercept that navigation, read the authorization code (and
// state) from the URL, close the doomed tab, and relay the result to the
// add-identity page that started the flow.
//
// The add-identity page (a normal extension tab) holds the WASM session state
// across the login, so this worker only needs to wake up for the redirect; it
// does not need to survive the whole flow.
//
// The worker also routes identity-wallet login: when a verifier page (via the
// content script) asks the wallet to authenticate, the worker opens the consent
// + signing page (auth.html), then relays its result back to the verifier tab.
// Pending correlations live in chrome.storage.session so they survive the
// worker being suspended while the user decides.

import { log, logSend, logRecv } from './src/log.js'

const REDIRECT_PREFIX = 'http://localhost:10001/login-callback'

chrome.webNavigation.onBeforeNavigate.addListener(
  (details) => {
    // Only top-level navigations to our redirect URI.
    if (details.frameId !== 0) return

    const url = new URL(details.url)
    const result = {
      type: 'byoid_oidc_result',
      code: url.searchParams.get('code'),
      state: url.searchParams.get('state'),
      error: url.searchParams.get('error'),
      errorDescription: url.searchParams.get('error_description'),
    }

    // Relay to the add-identity page(s). It matches on state.
    chrome.runtime.sendMessage(result).catch(() => {})

    // Close the tab before it renders a connection-refused error.
    chrome.tabs.remove(details.tabId).catch(() => {})
  },
  { url: [{ urlPrefix: REDIRECT_PREFIX }] },
)

// Identity-wallet login routing.
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg) return

  // A verifier page (via the content script) asks the wallet to authenticate.
  if (msg.type === 'wallet-authenticate') {
    const verifierTabId = sender.tab && sender.tab.id
    if (verifierTabId == null) return

    logRecv('background', 'content', 'wallet-authenticate', {
      requestId: msg.requestId,
      email: msg.email,
    })
    const params = new URLSearchParams({
      requestId: msg.requestId,
      email: msg.email || '',
      challenge: msg.challenge || '',
      issuer: msg.issuer || '',
      origin: msg.origin || '',
    })
    chrome.tabs.create(
      { url: chrome.runtime.getURL('auth.html?' + params.toString()) },
      (authTab) => {
        log('background', 'opened consent page (auth.html) for request', {
          requestId: msg.requestId,
        })
        // Remember how to route this request's result back to the verifier tab.
        chrome.storage.session.set({
          ['pending:' + msg.requestId]: { verifierTabId, authTabId: authTab.id },
        })
      },
    )
    return
  }

  // The consent/signing page reports the outcome.
  if (msg.type === 'wallet-auth-complete') {
    logRecv('background', 'auth-page', 'wallet-auth-complete', {
      requestId: msg.requestId,
      ok: msg.ok,
      error: msg.error,
    })
    const key = 'pending:' + msg.requestId
    chrome.storage.session.get(key).then((data) => {
      const pending = data[key]
      if (!pending) return
      chrome.storage.session.remove(key)
      logSend('background', 'content', 'wallet-auth-result', {
        requestId: msg.requestId,
        ok: msg.ok,
      })
      chrome.tabs
        .sendMessage(pending.verifierTabId, {
          type: 'wallet-auth-result',
          requestId: msg.requestId,
          ok: msg.ok,
          pkt: msg.pkt,
          osm: msg.osm,
          error: msg.error,
        })
        .catch(() => {})
      // Close the auth tab if it is still open.
      if (pending.authTabId != null) {
        chrome.tabs.remove(pending.authTabId).catch(() => {})
      }
    })
    return
  }
})
