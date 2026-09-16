// Consent + signing page for identity-wallet login.
//
// Opened by the background worker as auth.html?requestId=...&email=...&
// challenge=...&issuer=...&origin=... when a verifier page asks the wallet to
// authenticate. It finds the matching PK Token, asks the user to consent, and
// on approval signs the verifier's challenge with the token's committed private
// key (proof-of-possession) via WASM. The result is sent back to the background
// worker, which relays it to the verifier page. The private key never leaves
// the extension.

import { getWallet, isExpired } from './src/wallet.js'
import { mountProviderPicker } from './src/picker.js'
import { log, abbrev } from './src/log.js'

const params = new URLSearchParams(window.location.search)
const requestId = params.get('requestId')
const email = params.get('email') || ''
const challenge = params.get('challenge') || ''
const issuer = params.get('issuer') || ''
const origin = params.get('origin') || 'A website'

const statusEl = document.getElementById('status')
const errorEl = document.getElementById('error')

function setStatus(msg) {
  statusEl.hidden = false
  statusEl.textContent = msg
}
function showError(msg) {
  errorEl.hidden = false
  errorEl.textContent = msg
}

// complete reports the outcome to the background worker (which relays it to the
// verifier page and closes this tab).
function complete(result) {
  chrome.runtime.sendMessage({ type: 'wallet-auth-complete', requestId, ...result })
}

// Send a cancellation if the user closes the tab without deciding, so the
// verifier is not left waiting.
let decided = false
window.addEventListener('beforeunload', () => {
  if (!decided) complete({ ok: false, error: 'cancelled' })
})

async function loadWasm() {
  const go = new Go()
  const resp = await fetch('pkt.wasm')
  const bytes = await resp.arrayBuffer()
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject)
  go.run(instance)
  await new Promise((r) => setTimeout(r, 0))
  if (typeof globalThis.pktSignChallenge !== 'function') {
    throw new Error('WASM did not export pktSignChallenge')
  }
}

// matchesIssuer reports whether an entry's issuer matches the required issuer
// (trailing slash ignored). When no issuer is required (EBIA), any matches.
function matchesIssuer(entry) {
  if (!issuer) return true
  return (entry.iss || '').replace(/\/$/, '') === issuer.replace(/\/$/, '')
}

// findToken classifies the wallet's tokens for this email/issuer:
//   { status: 'ok', entry }       usable token found
//   { status: 'expired', entry }  a token exists but is expired or unusable
//                                   (e.g. no stored key), so it must be refreshed
//   { status: 'none' }            no token for this email/issuer at all
async function findToken() {
  const wallet = await getWallet()
  const candidates = wallet.filter((e) => e.email === email && matchesIssuer(e))
  if (candidates.length === 0) return { status: 'none' }

  // A token is usable only if it is unexpired and has a stored private key to
  // sign the challenge with.
  const usable = candidates.find((e) => e.privateJwk && !isExpired(e))
  if (usable) return { status: 'ok', entry: usable }

  // Otherwise a token exists but needs refreshing. Prefer the most recently
  // added one for display.
  const newest = candidates.sort((a, b) => (b.addedAt || 0) - (a.addedAt || 0))[0]
  return { status: 'expired', entry: newest }
}

// openAddOrRefresh opens the add-identity flow for a provider, carrying this
// login request along so that, after a successful (re-)authentication, the add
// page returns here to complete proof-of-possession. It deliberately does NOT
// abort the original request -- we keep it alive and resume it.
function openAddOrRefresh(op) {
  const resume = new URLSearchParams({
    op,
    requestId,
    email,
    challenge,
    issuer,
    origin,
  })
  chrome.tabs.create({ url: chrome.runtime.getURL(`add.html?${resume.toString()}`) })
  // Keep the original request pending; the add page will reopen this consent
  // flow. Mark decided so the beforeunload handler does not cancel it.
  decided = true
  window.close()
}

async function main() {
  document.getElementById('email').textContent = email
  document.getElementById('email2').textContent = email
  document.getElementById('email3').textContent = email
  document.getElementById('origin').textContent = origin

  const found = await findToken()

  if (found.status === 'none') {
    // No token for this email at all: let the user choose which OP to add,
    // then resume this login. Same picker UX as the popup's Add Identity.
    document.getElementById('notoken').hidden = false
    mountProviderPicker(
      document.getElementById('add'),
      document.getElementById('addMenu'),
      (op) => openAddOrRefresh(op),
    )
    document.getElementById('cancel').onclick = () => {
      decided = true
      complete({ ok: false, error: 'cancelled' })
      window.close()
    }
    return
  }

  if (found.status === 'expired') {
    // A token exists but is expired (or has no stored key): refresh it with the
    // same provider it came from (the OP is already known), then resume login.
    document.getElementById('expired').hidden = false
    document.getElementById('expdetail').textContent =
      `${found.entry.email} · ${found.entry.providerLabel || found.entry.provider || 'issuer'}`
    document.getElementById('refresh').onclick = () =>
      openAddOrRefresh(found.entry.provider || 'microsoft')
    document.getElementById('cancel2').onclick = () => {
      decided = true
      complete({ ok: false, error: 'cancelled' })
      window.close()
    }
    return
  }

  const entry = found.entry

  // Show consent.
  document.getElementById('prompt').hidden = false
  document.getElementById('tokdetail').textContent =
    `${entry.email} · ${entry.providerLabel || entry.provider || 'issuer'}`

  document.getElementById('deny').onclick = () => {
    decided = true
    complete({ ok: false, error: 'denied' })
    window.close()
  }

  document.getElementById('approve').onclick = async () => {
    decided = true
    document.getElementById('prompt').hidden = true
    setStatus('Signing challenge…')
    log('auth', 'user approved; signing challenge with committed key (PoP)', {
      email,
      challenge,
      issuer: issuer || '(any — EBIA)',
      pkt: abbrev(entry.pkt),
    })
    try {
      await loadWasm()
      const res = globalThis.pktSignChallenge(entry.privateJwk, entry.pkt, challenge)
      if (!res || !res.ok) {
        throw new Error((res && res.error) || 'failed to sign challenge')
      }
      log('auth', 'proof-of-possession produced (signed message)', {
        osm: abbrev(res.osm),
      })
      setStatus('Done. You can return to the sign-in page.')
      complete({ ok: true, pkt: entry.pkt, osm: res.osm })
      setTimeout(() => window.close(), 800)
    } catch (e) {
      showError(e.message || String(e))
      complete({ ok: false, error: e.message || String(e) })
    }
  }
}

main().catch((e) => showError(e.message || String(e)))
