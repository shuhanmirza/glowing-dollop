// PK Token wallet storage.
//
// The wallet is a list of PK Tokens the user has added, persisted in
// chrome.storage.local. Each entry is one credential: an (email, provider)
// pair. The same email at two different OpenID Providers (e.g. the same address
// used for both a Google and a Microsoft account) is two distinct credentials
// and both are kept. Re-adding or refreshing the same identity at the same
// provider replaces just that entry.
//
// Each entry stores the PK Token and its ephemeral private key (JWK) so the
// token can prove possession when signing in to a verifier. "Refresh" re-runs
// the login to mint a fresh token. (The key is currently stored extractably in
// chrome.storage.local; hardening it to a non-extractable WebCrypto key is a
// follow-up.)

const KEY = 'wallet'

// entryId is the stable identity key for a wallet entry: one credential per
// (provider, email). We prefer the provider id; if absent (older entries) we
// fall back to the issuer, then to email alone.
export function entryId(entry) {
  const realm = entry.provider || entry.iss || ''
  return `${realm}::${entry.email}`
}

// getWallet returns the list of stored identities (possibly empty).
export async function getWallet() {
  const data = await chrome.storage.local.get(KEY)
  return Array.isArray(data[KEY]) ? data[KEY] : []
}

// getById returns the entry with the given entryId, or undefined.
export async function getById(id) {
  const wallet = await getWallet()
  return wallet.find((e) => entryId(e) === id)
}

// upsertIdentity adds or replaces the entry for this (provider, email). It
// stamps entry.id so callers can address it stably.
export async function upsertIdentity(entry) {
  entry.id = entryId(entry)
  const wallet = await getWallet()
  const next = wallet.filter((e) => entryId(e) !== entry.id)
  next.push(entry)
  next.sort(
    (a, b) => a.email.localeCompare(b.email) || entryId(a).localeCompare(entryId(b)),
  )
  await chrome.storage.local.set({ [KEY]: next })
  return next
}

// removeIdentity deletes the entry with the given entryId.
export async function removeIdentity(id) {
  const wallet = await getWallet()
  const next = wallet.filter((e) => entryId(e) !== id)
  await chrome.storage.local.set({ [KEY]: next })
  return next
}

// isExpired reports whether an entry's ID token expiry (unix seconds) has
// passed. Entries without an expiry are treated as expired to be safe.
export function isExpired(entry) {
  if (!entry.exp) return true
  return Date.now() >= entry.exp * 1000
}
