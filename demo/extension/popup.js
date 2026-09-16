// Popup: the PK Token wallet view.
//
// Lists the identities the user has added, showing each one's email, the
// provider it came from, and whether its token is still valid. "Add Identity"
// reveals a provider picker; choosing one opens the add-identity flow for that
// OP. "Refresh" re-runs the login for the entry's own provider, and "Remove"
// deletes the entry. The OIDC + WASM work happens in the add-identity tab,
// which must persist across the login round-trip.

import { getWallet, removeIdentity, isExpired, entryId } from './src/wallet.js'
import { issuerHost } from './src/pkt.js'
import { mountProviderPicker } from './src/picker.js'

const listEl = document.getElementById('list')
const emptyEl = document.getElementById('empty')
const addBtn = document.getElementById('add')
const pickerEl = document.getElementById('picker')

// openAddFlow opens the add-identity tab for a given provider id.
function openAddFlow(providerId) {
  const url = chrome.runtime.getURL(`add.html?op=${encodeURIComponent(providerId)}`)
  chrome.tabs.create({ url })
  window.close() // move focus to the flow tab
}

// openDetails opens the read-only details page for an identity (by entry id).
function openDetails(id) {
  const url = chrome.runtime.getURL(`details.html?id=${encodeURIComponent(id)}`)
  chrome.tabs.create({ url })
  window.close()
}

function fmtExpiry(entry) {
  if (!entry.exp) return 'unknown'
  return new Date(entry.exp * 1000).toLocaleString()
}

async function render() {
  const wallet = await getWallet()
  listEl.innerHTML = ''
  emptyEl.hidden = wallet.length > 0

  for (const entry of wallet) {
    const expired = isExpired(entry)

    const li = document.createElement('li')
    li.className = 'item'

    const row = document.createElement('div')
    row.className = 'item-row'

    const email = document.createElement('span')
    email.className = 'item-email'
    email.textContent = entry.email

    const badge = document.createElement('span')
    badge.className = 'badge ' + (expired ? 'badge-expired' : 'badge-valid')
    badge.textContent = expired ? 'Expired' : 'Valid'

    row.append(email, badge)

    // Issuer chip — visually distinct from the validity badge.
    const issuer = document.createElement('div')
    issuer.className = 'issuer'
    issuer.textContent = '🌐 ' + issuerHost(entry.iss)
    issuer.title = entry.iss || ''

    const meta = document.createElement('div')
    meta.className = 'item-meta'
    const via = entry.providerLabel ? `${entry.providerLabel} · ` : ''
    meta.textContent = via + (expired ? 'Expired: ' : 'Valid until: ') + fmtExpiry(entry)

    const actions = document.createElement('div')
    actions.className = 'item-actions'

    const details = document.createElement('button')
    details.className = 'link'
    details.textContent = 'Details'
    details.onclick = () => openDetails(entryId(entry))

    const refresh = document.createElement('button')
    refresh.className = 'link'
    refresh.textContent = 'Refresh'
    // Re-authenticate with the same provider this identity came from.
    refresh.onclick = () => openAddFlow(entry.provider || 'microsoft')

    const remove = document.createElement('button')
    remove.className = 'link link-danger'
    remove.textContent = 'Remove'
    remove.onclick = async () => {
      await removeIdentity(entryId(entry))
      render()
    }

    actions.append(details, refresh, remove)
    li.append(row, issuer, meta, actions)
    listEl.append(li)
  }
}

// "Add Identity" opens a dropdown of OpenID Providers; picking one starts the
// add flow for that OP.
mountProviderPicker(addBtn, pickerEl, openAddFlow)

// Keep the list fresh if a token is added/removed while the popup is open.
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.wallet) render()
})

render()
