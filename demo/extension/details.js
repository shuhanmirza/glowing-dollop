// Identity details page.
//
// Opened in a tab as details.html?email=<email>. Loads the wallet entry, decodes
// its PK Token, and shows all ID token claims plus the PK Token structure (the
// OP signature and the user's proof-of-possession signature over the committed
// ephemeral key). Read-only; intended for inspecting/showcasing a token.

import { getWallet, getById, isExpired } from './src/wallet.js'
import { parsePkToken, describeSignature, issuerHost } from './src/pkt.js'

const titleEl = document.getElementById('title')
const errorEl = document.getElementById('error')
const contentEl = document.getElementById('content')

document.getElementById('close').onclick = () => window.close()

// Claims whose values are unix timestamps; shown with a human-readable date.
const TIME_CLAIMS = new Set(['iat', 'exp', 'nbf', 'auth_time'])

function fmtValue(key, value) {
  if (TIME_CLAIMS.has(key) && typeof value === 'number') {
    return `${value}  (${new Date(value * 1000).toLocaleString()})`
  }
  if (value !== null && typeof value === 'object') {
    return JSON.stringify(value)
  }
  return String(value)
}

// addRow appends a key/value row to a table body.
function addRow(tbody, key, value, opts = {}) {
  const tr = document.createElement('tr')
  const k = document.createElement('td')
  k.className = 'claim-key'
  k.textContent = key
  const v = document.createElement('td')
  v.className = 'claim-val' + (opts.mono ? ' mono' : '')
  v.textContent = value
  tr.append(k, v)
  tbody.append(tr)
}

async function main() {
  const params = new URLSearchParams(window.location.search)
  const id = params.get('id')
  // Look up by stable entry id; fall back to email for older links.
  let entry
  if (id) {
    entry = await getById(id)
  } else {
    const email = params.get('email')
    const wallet = await getWallet()
    entry = wallet.find((e) => e.email === email)
  }

  if (!entry) {
    errorEl.hidden = false
    errorEl.textContent = 'Identity not found in the wallet.'
    return
  }

  titleEl.textContent = entry.email
  contentEl.hidden = false

  let parsed
  try {
    parsed = parsePkToken(entry.pkt)
  } catch (e) {
    errorEl.hidden = false
    errorEl.textContent = 'Could not decode the stored PK Token: ' + e.message
    return
  }
  const { claims, signatures, raw } = parsed

  // Summary chips.
  const issuerEl = document.getElementById('issuer')
  issuerEl.textContent = '🌐 ' + issuerHost(claims.iss || entry.iss)
  issuerEl.title = claims.iss || entry.iss || ''

  const expired = isExpired(entry)
  const statusEl = document.getElementById('status')
  statusEl.classList.add(expired ? 'badge-expired' : 'badge-valid')
  statusEl.textContent = expired ? 'Expired' : 'Valid'

  document.getElementById('provider').textContent =
    entry.providerLabel || entry.provider || 'unknown provider'

  // ID token claims (sorted for stable display).
  const claimsBody = document.getElementById('claims')
  for (const key of Object.keys(claims).sort()) {
    addRow(claimsBody, key, fmtValue(key, claims[key]))
  }

  // PK Token structure.
  const structBody = document.getElementById('structure')
  addRow(structBody, 'signatures', String(signatures.length))
  signatures.forEach((h, i) => {
    const parts = [describeSignature(h)]
    if (h.alg) parts.push(`alg=${h.alg}`)
    if (h.typ) parts.push(`typ=${h.typ}`)
    addRow(structBody, `  signature[${i}]`, parts.join('  ·  '))
    // The CIC signature carries the committed ephemeral public key (upk) and
    // randomness (rz) -- the heart of the OpenPubkey commitment.
    if (h.upk) {
      const upk = h.upk
      addRow(structBody, '    committed key (upk)', `kty=${upk.kty || '?'} crv=${upk.crv || '?'}`, { mono: true })
      if (upk.x) addRow(structBody, '    upk.x', upk.x, { mono: true })
      if (upk.y) addRow(structBody, '    upk.y', upk.y, { mono: true })
    }
    if (h.rz) addRow(structBody, '    randomness (rz)', h.rz, { mono: true })
  })
  if (entry.addedAt) {
    addRow(structBody, 'added to wallet', new Date(entry.addedAt * 1000).toLocaleString())
  }

  // Raw PK Token, pretty-printed.
  document.getElementById('raw').textContent = JSON.stringify(raw, null, 2)
}

main().catch((e) => {
  errorEl.hidden = false
  errorEl.textContent = 'Error: ' + (e.message || String(e))
})
