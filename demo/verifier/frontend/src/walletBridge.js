// Page-side bridge to identity-wallet browser extensions.
//
// Mirrors the EIP-6963 discovery shape with our own namespaced messages, so it
// never collides with crypto-wallet extensions. All communication is via
// window.postMessage on this page's own origin; the extension's content script
// relays to/from the extension. The private key never reaches this page — we
// only ever receive a PK Token and a signed challenge (proof-of-possession).

import { log, logSend, logRecv, abbrev } from './log.js'

// detectWallets asks any installed identity wallets to announce themselves and
// collects the responses for a short window. Returns a list of
// { uuid, rdns, name }.
export function detectWallets(timeoutMs = 500) {
  return new Promise((resolve) => {
    const found = new Map()

    function onMessage(event) {
      if (event.source !== window) return
      const msg = event.data
      if (!msg || msg.source !== 'byoid-ext') return
      if (msg.type === 'announceProvider' && msg.provider) {
        logRecv('verifier-page', 'extension', 'announceProvider', {
          rdns: msg.provider.rdns,
          name: msg.provider.name,
        })
        found.set(msg.provider.rdns, msg.provider)
      }
    }

    window.addEventListener('message', onMessage)
    // Ask wallets to announce (they also announce proactively on load).
    logSend('verifier-page', 'extension(s)', 'requestProvider', {
      note: 'discovering identity wallets',
    })
    window.postMessage({ source: 'byoid-page', type: 'requestProvider' }, window.location.origin)

    setTimeout(() => {
      window.removeEventListener('message', onMessage)
      log('verifier-page', `wallet discovery done: ${found.size} wallet(s)`, [
        ...found.keys(),
      ])
      resolve([...found.values()])
    }, timeoutMs)
  })
}

// authenticate asks a specific wallet to prove control of an email by signing a
// challenge with the key committed in its PK Token. Resolves with { pkt, osm }
// or rejects with an error.
export function authenticate({ rdns, email, challenge, issuer }, timeoutMs = 300000) {
  return new Promise((resolve, reject) => {
    const requestId = crypto.randomUUID()

    function onMessage(event) {
      if (event.source !== window) return
      const msg = event.data
      if (!msg || msg.source !== 'byoid-ext' || msg.type !== 'authResult') return
      if (msg.requestId !== requestId) return
      cleanup()
      if (msg.ok) {
        logRecv('verifier-page', 'extension', 'authResult (ok)', {
          requestId,
          pkt: abbrev(msg.pkt),
          osm: abbrev(msg.osm),
        })
        resolve({ pkt: msg.pkt, osm: msg.osm })
      } else {
        logRecv('verifier-page', 'extension', 'authResult (declined)', {
          requestId,
          error: msg.error,
        })
        reject(new Error(msg.error || 'wallet declined'))
      }
    }

    function cleanup() {
      window.removeEventListener('message', onMessage)
      clearTimeout(timer)
    }

    const timer = setTimeout(() => {
      cleanup()
      reject(new Error('the wallet did not respond in time'))
    }, timeoutMs)

    window.addEventListener('message', onMessage)
    logSend('verifier-page', 'extension', 'authenticate', {
      requestId,
      rdns,
      email,
      challenge,
      issuer: issuer || '(any — EBIA)',
    })
    window.postMessage(
      { source: 'byoid-page', type: 'authenticate', requestId, rdns, email, challenge, issuer },
      window.location.origin,
    )
  })
}
