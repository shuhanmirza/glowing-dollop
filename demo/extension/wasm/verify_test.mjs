// End-to-end proof that the WASM shim produces a valid PK Token.
//
// Runs the real pkt.wasm in Node: generates a commitment, mints a mock
// OP-signed ID token whose nonce is the commitment, assembles a PK Token, then
// cryptographically verifies BOTH signatures (the OP's RS256 signature and the
// user's ES256 proof-of-possession over the committed key). This exercises the
// full WASM boundary without needing an interactive Microsoft login.
//
// Run from demo/extension after building: node wasm/verify_test.mjs

import { readFileSync } from 'node:fs'
import { webcrypto as crypto } from 'node:crypto'
import { createRequire } from 'node:module'

const require = createRequire(import.meta.url)
// Node 22 exposes globalThis.crypto already (read-only); no need to assign it.

function b64urlToBytes(s) {
  return new Uint8Array(Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64'))
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
  // Load Go's WASM runtime glue and instantiate the module.
  require('../wasm_exec.js')
  const go = new globalThis.Go()
  const bytes = readFileSync('pkt.wasm')
  const { instance } = await WebAssembly.instantiate(bytes, go.importObject)
  go.run(instance) // registers funcs then blocks; do not await
  await new Promise((r) => setTimeout(r, 0))

  check('pktGenCommitment exported', typeof globalThis.pktGenCommitment === 'function')
  check('pktAssemble exported', typeof globalThis.pktAssemble === 'function')

  // 1. Commitment.
  const commit = globalThis.pktGenCommitment()
  check('genCommitment ok', commit.ok === true)
  check('nonce is non-empty', typeof commit.nonce === 'string' && commit.nonce.length > 0)
  check('sid returned', typeof commit.sid === 'string')

  // 2. Mock OP: RS256 key + ID token whose nonce is the commitment.
  const opKey = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify'],
  )
  const now = Math.floor(Date.now() / 1000)
  const header = { alg: 'RS256', typ: 'JWT', kid: 'mock-op-key' }
  const payload = {
    iss: 'https://login.microsoftonline.com/9188040d/v2.0',
    aud: '096ce0a3-5e72-4da8-9c86-12924b294a01',
    sub: 'mock-subject',
    email: 'demo@outlook.com',
    exp: now + 3600,
    iat: now,
    nonce: commit.nonce,
  }
  const signingInput = `${jsonToB64url(header)}.${jsonToB64url(payload)}`
  const opSig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', opKey.privateKey, Buffer.from(signingInput))
  const idToken = `${signingInput}.${bytesToB64url(new Uint8Array(opSig))}`

  // 3. Assemble the PK Token.
  const res = globalThis.pktAssemble(commit.sid, idToken)
  check('assemble ok', res.ok === true)
  if (!res.ok) {
    console.log('    error:', res.error)
    return
  }

  // 4. Parse and verify the PK Token.
  const pkt = JSON.parse(res.pkt)
  check('pkt has payload', typeof pkt.payload === 'string')
  check('pkt has two signatures (OP + CIC)', Array.isArray(pkt.signatures) && pkt.signatures.length === 2)

  const sharedPayload = pkt.payload
  const [opSigObj, cicSigObj] = pkt.signatures

  // Payload must be the ID token's payload unchanged.
  const pktPayload = JSON.parse(Buffer.from(b64urlToBytes(sharedPayload)))
  check('payload nonce == commitment', pktPayload.nonce === commit.nonce)
  check('payload email preserved', pktPayload.email === 'demo@outlook.com')

  // 4a. Verify the OP signature over protected.payload.
  const opOk = await crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    opKey.publicKey,
    b64urlToBytes(opSigObj.signature),
    Buffer.from(`${opSigObj.protected}.${sharedPayload}`),
  )
  check('OP RS256 signature verifies', opOk)

  // 4b. The CIC signature: parse protected header, confirm it commits, verify PoP.
  const cicHeader = JSON.parse(Buffer.from(b64urlToBytes(cicSigObj.protected)))
  check('CIC typ == CIC', cicHeader.typ === 'CIC')
  check('CIC alg == ES256', cicHeader.alg === 'ES256')
  check('CIC carries user public key (upk)', !!cicHeader.upk && cicHeader.upk.kty === 'EC')
  check('CIC carries rz (randomness)', typeof cicHeader.rz === 'string')

  const upk = await crypto.subtle.importKey(
    'jwk',
    { kty: cicHeader.upk.kty, crv: cicHeader.upk.crv, x: cicHeader.upk.x, y: cicHeader.upk.y },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify'],
  )
  const cicOk = await crypto.subtle.verify(
    { name: 'ECDSA', hash: 'SHA-256' },
    upk,
    b64urlToBytes(cicSigObj.signature),
    Buffer.from(`${cicSigObj.protected}.${sharedPayload}`),
  )
  check('CIC ES256 proof-of-possession verifies', cicOk)

  // 5. Assemble again should fail (session consumed).
  const again = globalThis.pktAssemble(commit.sid, idToken)
  check('session is single-use', again.ok === false)

  console.log(failures === 0 ? '\nALL PASS' : `\n${failures} FAILURE(S)`)
  process.exit(failures === 0 ? 0 : 1)
}

main().catch((e) => {
  console.error('harness error:', e)
  process.exit(1)
})
