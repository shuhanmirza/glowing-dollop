// Add-identity flow: run a real OIDC login against the chosen OpenID Provider
// and store the resulting PK Token in the wallet.
//
// This page hosts the WASM OpenPubkey client and drives the OIDC flow. It runs
// in a normal extension tab (not the popup) so its WASM session state survives
// the login round-trip, which happens in a separate tab. The provider to use is
// passed as the `op` query parameter (e.g. add.html?op=google).
//
// Steps:
//   1. Instantiate the WASM module.
//   2. genCommitment -> ephemeral key + nonce (CIC hash) held in WASM memory.
//   3. Open the provider's authorization URL in a new tab.
//   4. The background worker intercepts the loopback redirect and sends us the
//      authorization code.
//   5. Exchange the code for an ID token, then WASM assembles the PK Token.
//   6. Store it in the wallet, keyed by email.

import { beginAuth, exchangeCode, decodeJwtPayload } from './src/oidc.js'
import { getProvider } from './src/config.js'
import { upsertIdentity } from './src/wallet.js'
import { burst } from './src/confetti.js'

const statusEl = document.getElementById('status')
const detailEl = document.getElementById('detail')
const closeBtn = document.getElementById('close')

// Resume context: when this page was opened from a verifier login flow (the
// consent page had no usable token and sent the user here to add/refresh one),
// these carry the original request so we can return to the consent page and
// complete proof-of-possession instead of ending at a success screen.
const q = new URLSearchParams(window.location.search)
const opId = q.get('op') || 'microsoft'
const resume = {
  requestId: q.get('requestId') || '',
  email: q.get('email') || '',
  challenge: q.get('challenge') || '',
  issuer: q.get('issuer') || '',
  origin: q.get('origin') || '',
}
const isResume = !!resume.requestId
// Set before any intentional close so beforeunload does not abort a request we
// are deliberately resuming or have already settled.
let settled = false

// If the user closes this tab mid-refresh without finishing, abort the original
// login request so the verifier is not left waiting.
window.addEventListener('beforeunload', () => {
  if (isResume && !settled) {
    chrome.runtime.sendMessage({
      type: 'wallet-auth-complete',
      requestId: resume.requestId,
      ok: false,
      error: 'cancelled',
    })
  }
})

function setStatus(msg) {
  statusEl.textContent = msg
}
function setDetail(html) {
  detailEl.innerHTML = html
}
function fail(msg) {
  statusEl.textContent = 'Could not add identity'
  statusEl.classList.add('status-error')
  setDetail(`<p class="err">${msg}</p>`)
  // If this was part of a login flow, abort the original request so the
  // verifier stops waiting.
  if (isResume) {
    settled = true
    chrome.runtime.sendMessage({
      type: 'wallet-auth-complete',
      requestId: resume.requestId,
      ok: false,
      error: 'refresh-failed',
    })
  }
  showClose()
}
function showClose() {
  closeBtn.hidden = false
  closeBtn.onclick = () => window.close()
}

// loadWasm instantiates pkt.wasm and resolves once the exported functions are
// available on the global object.
async function loadWasm() {
  const go = new Go()
  const resp = await fetch('pkt.wasm')
  const bytes = await resp.arrayBuffer()
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject)
  // Run the Go program; it registers the functions and then blocks.
  go.run(instance)
  // go.run schedules the registration synchronously before it blocks, but yield
  // once to be safe.
  await new Promise((r) => setTimeout(r, 0))
  if (typeof globalThis.pktGenCommitment !== 'function') {
    throw new Error('WASM did not export pktGenCommitment')
  }
}

// waitForCode resolves with the authorization code once the background worker
// relays the redirect matching our state.
function waitForCode(expectedState) {
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      chrome.runtime.onMessage.removeListener(listener)
      reject(new Error('timed out waiting for the login to complete'))
    }, 5 * 60 * 1000)

    function listener(msg) {
      if (!msg || msg.type !== 'byoid_oidc_result') return
      if (msg.state !== expectedState) return
      clearTimeout(timeout)
      chrome.runtime.onMessage.removeListener(listener)
      if (msg.error) {
        reject(new Error(msg.errorDescription || msg.error))
      } else if (!msg.code) {
        reject(new Error('no authorization code in redirect'))
      } else {
        resolve(msg.code)
      }
    }
    chrome.runtime.onMessage.addListener(listener)
  })
}

async function run() {
  try {
    // Resolve the provider from the ?op= query parameter (default: microsoft).
    const provider = getProvider(opId)
    document.title = `Add identity · ${provider.label}`

    setStatus('Loading OpenPubkey client…')
    await loadWasm()

    setStatus('Preparing commitment…')
    const commit = globalThis.pktGenCommitment()
    if (!commit || !commit.ok) {
      throw new Error((commit && commit.error) || 'failed to generate commitment')
    }

    setStatus(`Opening ${provider.label} sign-in…`)
    const { url, state, codeVerifier, tokenEndpoint } = await beginAuth(provider, commit.nonce)
    const codePromise = waitForCode(state)
    await chrome.tabs.create({ url })
    setStatus('Waiting for you to sign in…')
    setDetail(`<p>A ${provider.label} sign-in tab has opened. Complete sign-in there.</p>`)

    const code = await codePromise
    setStatus('Exchanging code for token…')
    setDetail('')
    const tokens = await exchangeCode(provider, tokenEndpoint, code, codeVerifier)

    setStatus('Assembling PK Token…')
    const assembled = globalThis.pktAssemble(commit.sid, tokens.id_token)
    if (!assembled || !assembled.ok) {
      throw new Error((assembled && assembled.error) || 'failed to assemble PK Token')
    }

    const claims = decodeJwtPayload(tokens.id_token)
    const email = claims.email || claims.preferred_username || claims.upn
    if (!email) {
      throw new Error('ID token has no email/preferred_username claim')
    }

    await upsertIdentity({
      email,
      pkt: assembled.pkt,
      // Ephemeral private key (JWK) needed to prove possession when
      // authenticating to a verifier. Stored in chrome.storage.local for this
      // milestone; hardening to a non-extractable WebCrypto key is a follow-up.
      privateJwk: assembled.privateJwk,
      provider: provider.id,
      providerLabel: provider.label,
      iss: claims.iss || '',
      exp: claims.exp || 0,
      addedAt: Math.floor(Date.now() / 1000),
    })

    // If we came from a verifier login flow, return to the consent page to
    // complete proof-of-possession with the fresh token, rather than ending
    // here. Use the original login-flow values (the verifier's challenge etc.).
    if (isResume) {
      settled = true
      setStatus('Token refreshed. Returning to sign-in…')
      const back = new URLSearchParams({
        requestId: resume.requestId,
        email: resume.email,
        challenge: resume.challenge,
        issuer: resume.issuer,
        origin: resume.origin,
      })
      chrome.tabs.create({ url: chrome.runtime.getURL(`auth.html?${back.toString()}`) })
      window.close()
      return
    }

    setStatus('🎉 Identity added!')
    statusEl.classList.add('status-success')
    setDetail(
      `<p>Added <strong>${email}</strong> (via ${provider.label}) to your PK Token wallet.</p>` +
        `<p class="muted">You can close this tab and open the extension popup.</p>`,
    )
    burst()
    showClose()
  } catch (e) {
    fail(e.message || String(e))
  }
}

run()
