// Helpers for reading a stored PK Token for display.
//
// A PK Token is a JWS JSON serialization: { payload, signatures: [...] }, where
// payload is the base64url ID-token claims and each signature has a base64url
// protected header. The two signatures are the OP's signature over the ID token
// and the user's CIC signature (proof-of-possession of the committed key).

function b64urlToObject(s) {
  const json = atob(String(s).replace(/-/g, '+').replace(/_/g, '/'))
  return JSON.parse(json)
}

// parsePkToken decodes a PK Token into its shared payload claims and the
// protected headers of its signatures.
export function parsePkToken(pktJson) {
  const pkt = typeof pktJson === 'string' ? JSON.parse(pktJson) : pktJson
  const claims = b64urlToObject(pkt.payload)
  const signatures = (pkt.signatures || []).map((s) => b64urlToObject(s.protected))
  return { claims, signatures, raw: pkt }
}

// describeSignature labels a PK Token signature from its protected header: the
// user's CIC signature (proof-of-possession) vs the OP's signature.
export function describeSignature(header) {
  return header && header.typ === 'CIC'
    ? 'User — proof-of-possession'
    : 'OpenID Provider'
}

// issuerHost returns just the host of an issuer URL, for compact display.
export function issuerHost(iss) {
  if (!iss) return 'unknown'
  try {
    return new URL(iss).host
  } catch (e) {
    return iss
  }
}
