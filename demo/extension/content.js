// Content script: the bridge between a verifier web page and the wallet.
//
// It follows the EIP-6963 shape (a page asks for providers, wallets announce
// themselves) but with our own namespaced messages so it never collides with
// crypto-wallet extensions. All page communication is via window.postMessage on
// the page's own origin; the actual signing happens in an extension page opened
// by the background worker, so the private key never enters the web page.
//
// Messages from the page (event.data.source === 'byoid-page'):
//   { type: 'requestProvider' }
//       -> we reply with 'announceProvider' describing this wallet.
//   { type: 'authenticate', requestId, email, challenge, issuer }
//       -> we relay to the background worker, which prompts the user and signs;
//          the result comes back as 'authResult'.
//
// Messages to the page (source === 'byoid-ext'):
//   { type: 'announceProvider', provider: { uuid, rdns, name } }
//   { type: 'authResult', requestId, ok, pkt, osm, error }

// Inline logger (content scripts injected via the manifest can't use ES module
// imports, so we can't share src/log.js here). Mirrors its format.
const STYLE = 'color:#7c4dff;font-weight:bold'
const abbrev = (v, n = 14) =>
  typeof v !== 'string' ? v : v.length <= n * 2 ? v : `${v.slice(0, n)}…(${v.length} chars)`
const log = (msg, fields) =>
  fields !== undefined
    ? console.log('%c[BYOID:content]', STYLE, msg, fields)
    : console.log('%c[BYOID:content]', STYLE, msg)
const logSend = (to, type, fields) => log(`→ send [${type}] to ${to}`, fields)
const logRecv = (from, type, fields) => log(`← recv [${type}] from ${from}`, fields)

const PROVIDER = {
  // A per-load UUID and a reverse-DNS id let a page distinguish multiple
  // wallets, exactly as EIP-6963 does for multiple crypto wallets.
  uuid: crypto.randomUUID(),
  rdns: 'com.cfdata.byoid',
  name: 'BYOID PK Token Wallet',
}

function announce(reason) {
  logSend('verifier-page', 'announceProvider', {
    rdns: PROVIDER.rdns,
    reason,
  })
  window.postMessage(
    { source: 'byoid-ext', type: 'announceProvider', provider: PROVIDER },
    window.location.origin,
  )
}

// Relay page -> background, and remember which page requests are outstanding so
// we can post the result back to the right one.
window.addEventListener('message', (event) => {
  if (event.source !== window) return
  const msg = event.data
  if (!msg || msg.source !== 'byoid-page') return

  if (msg.type === 'requestProvider') {
    logRecv('verifier-page', 'requestProvider')
    announce('requested')
    return
  }

  if (msg.type === 'authenticate') {
    logRecv('verifier-page', 'authenticate', {
      requestId: msg.requestId,
      email: msg.email,
      challenge: msg.challenge,
      issuer: msg.issuer || '(any)',
    })
    logSend('background', 'wallet-authenticate', { requestId: msg.requestId })
    chrome.runtime.sendMessage({
      type: 'wallet-authenticate',
      requestId: msg.requestId,
      email: msg.email,
      challenge: msg.challenge,
      issuer: msg.issuer || '',
      rdns: PROVIDER.rdns,
      origin: window.location.origin,
    })
  }
})

// Result relayed from the background worker (after the user approves and the
// challenge is signed) -> hand back to the page.
chrome.runtime.onMessage.addListener((msg) => {
  if (!msg || msg.type !== 'wallet-auth-result') return
  logRecv('background', 'wallet-auth-result', {
    requestId: msg.requestId,
    ok: msg.ok,
    error: msg.error,
  })
  logSend('verifier-page', 'authResult', {
    requestId: msg.requestId,
    ok: msg.ok,
    pkt: abbrev(msg.pkt),
    osm: abbrev(msg.osm),
  })
  window.postMessage(
    {
      source: 'byoid-ext',
      type: 'authResult',
      requestId: msg.requestId,
      ok: msg.ok,
      pkt: msg.pkt,
      osm: msg.osm,
      error: msg.error,
    },
    window.location.origin,
  )
})

// Announce proactively on load so a page already listening discovers us.
log('content script injected on ' + window.location.origin)
announce('page-load')
