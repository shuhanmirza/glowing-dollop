// Proof that the WASM proof-of-possession path works end-to-end.
//
// Runs the real pkt.wasm in Node: generates a commitment, mints a mock
// OP-signed ID token, assembles a PK Token (capturing the exported private
// JWK), signs a challenge with signChallenge, then verifies the resulting
// OpenPubkey signed message (OSM): the payload equals the challenge and the
// ES256 signature verifies against the ephemeral public key committed in the
// PK Token's CIC header. This mirrors what the Go verifier's
// VerifySignedMessage checks.
//
// Run from demo/extension after building: node wasm/pop_test.mjs

import { readFileSync } from 'node:fs'
import { webcrypto as crypto } from 'node:crypto'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)

function b64urlToBytes(s) {
  return new Uint8Array(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'))
}
function bytesToB64url(b) {
  return Buffer.from(b).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}
function jsonToB64url(o) {
  return bytesToB64url(Buffer.from(JSON.stringify(o)))
}

let failures = 0
function check(name, cond) {
  console.log(`  ${cond ? 'PASS' : 'FAIL'}  ${name}`)
  if (!cond) failures++
}

async function main() {
  require('../wasm_exec.js')
  const go = new globalThis.Go()
  const { instance } = await WebAssembly.instantiate(readFileSync('pkt.wasm'), go.importObject)
  go.run(instance)
  await new Promise((r) => setTimeout(r, 0))

  check('pktSignChallenge exported', typeof globalThis.pktSignChallenge === 'function')

  // Commitment + mock OP ID token.
  const commit = globalThis.pktGenCommitment()
  const opKey = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'RS256', typ: 'JWT', kid: 'mock' }
  const payload = {
    iss: 'https://accounts.google.com',
    aud: 'client-abc',
    sub: 'user-1',
    email: 'demo@gmail.com',
    exp: now + 3600,
    iat: now,
    nonce: commit.nonce,
  }
  const signingInput = `${jsonToB64url(header)}.${jsonToB64url(payload)}`
  const opSig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', opKey.privateKey, Buffer.from(signingInput))
  const idToken = `${signingInput}.${bytesToB64url(new Uint8Array(opSig))}`

  // Assemble: capture pkt + exported private JWK.
  const a = globalThis.pktAssemble(commit.sid, idToken)
  check('assemble ok', a.ok === true)
  check('assemble exported privateJwk', typeof a.privateJwk === 'string' && a.privateJwk.includes('"d"'))

  // Sign a fresh challenge with the stored key.
  const challenge = 'server-challenge-' + bytesToB64url(crypto.getRandomValues(new Uint8Array(16)))
  const s = globalThis.pktSignChallenge(a.privateJwk, a.pkt, challenge)
  check('signChallenge ok', s.ok === true)
  if (!s.ok) {
    console.log('    error:', s.error)
    process.exit(1)
  }

  // The OSM is a compact JWS: header.payload.signature.
  const [osmHeaderB64, osmPayloadB64, osmSigB64] = s.osm.split('.')
  check('osm has three parts', !!osmHeaderB64 && !!osmPayloadB64 && !!osmSigB64)

  const osmPayload = Buffer.from(b64urlToBytes(osmPayloadB64)).toString()
  check('osm payload equals challenge', osmPayload === challenge)

  // Recover the committed public key (upk) from the PK Token's CIC header.
  const pkt = JSON.parse(a.pkt)
  const cicSig = pkt.signatures.find((sig) => {
    const h = JSON.parse(Buffer.from(b64urlToBytes(sig.protected)).toString())
    return h.typ === 'CIC'
  })
  const cicHeader = JSON.parse(Buffer.from(b64urlToBytes(cicSig.protected)).toString())
  const upk = cicHeader.upk
  check('committed key is EC P-256', upk && upk.kty === 'EC' && upk.crv === 'P-256')

  const pubKey = await crypto.subtle.importKey(
    'jwk',
    { kty: upk.kty, crv: upk.crv, x: upk.x, y: upk.y },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )

  // The OSM signs header.payload with ES256 (raw r||s).
  const osmVerifies = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    pubKey,
    b64urlToBytes(osmSigB64),
    Buffer.from(`${osmHeaderB64}.${osmPayloadB64}`),
  )
  check('OSM signature verifies against committed key (proof-of-possession)', osmVerifies)

  // A signature by a different key must NOT verify (sanity).
  const other = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const otherVerifies = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    other.publicKey,
    b64urlToBytes(osmSigB64),
    Buffer.from(`${osmHeaderB64}.${osmPayloadB64}`),
  )
  check('OSM does NOT verify against an unrelated key', otherVerifies === false)

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((e) => {
  console.error('harness error:', e)
  process.exit(1)
})
