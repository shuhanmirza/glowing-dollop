//go:build js && wasm

// Command pktwasm is the browser-side OpenPubkey client, compiled to
// WebAssembly. It reuses OpenPubkey's own PK Token construction so the tokens
// this extension produces are byte-for-byte what an OpenPubkey verifier
// expects -- we do not reimplement the crypto in JavaScript.
//
// The OpenPubkey PK Token flow has two phases with a browser round-trip (the
// OIDC login) in between:
//
//  1. genCommitment: generate an ephemeral key pair and the Client Instance
//     Claims (CIC); the CIC hash is the value the caller must place in the
//     OIDC `nonce`. This commits the ephemeral public key inside the ID token
//     the OP will sign.
//  2. assemble: after the caller obtains the OP-signed ID token, sign the CIC
//     over it and combine the two into a PK Token. This also exports the
//     ephemeral private key (as a JWK) so the wallet can persist it and later
//     prove possession.
//
// Later, to authenticate to a Verifier:
//
//  3. signChallenge: sign a fresh challenge from the Verifier with the private
//     key committed in a stored PK Token, producing an OpenPubkey signed
//     message (proof-of-possession).
//
// The JavaScript side drives the OIDC requests and persistence; this module
// never touches the network.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"sync"
	"syscall/js"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/pktoken/clientinstance"
	"github.com/openpubkey/openpubkey/util"
)

// alg is the signature algorithm for the ephemeral key. ES256 keeps the key
// small and is well supported by the OpenPubkey verifier.
const alg = "ES256"

// session holds the per-login state that must survive the OIDC round-trip.
type session struct {
	signer crypto.Signer
	cic    *clientinstance.Claims
}

var (
	mu       sync.Mutex
	sessions = map[string]*session{}
	seq      int
)

func main() {
	js.Global().Set("pktGenCommitment", js.FuncOf(genCommitment))
	js.Global().Set("pktAssemble", js.FuncOf(assemble))
	js.Global().Set("pktSignChallenge", js.FuncOf(signChallenge))
	// Block forever; the exported functions are called from JS.
	select {}
}

// ok builds the {ok:true, ...} object the JS side expects.
func ok(fields map[string]any) any {
	fields["ok"] = true
	return js.ValueOf(fields)
}

// fail turns a Go error into a {ok:false, error} object rather than a panic.
func fail(err error) any {
	return js.ValueOf(map[string]any{"ok": false, "error": err.Error()})
}

// genCommitment() -> {ok, sid, nonce} generates the ephemeral key + CIC and
// returns the session id and the nonce (CIC hash) to embed in the OIDC request.
func genCommitment(this js.Value, args []js.Value) any {
	signer, err := util.GenKeyPair(alg)
	if err != nil {
		return fail(fmt.Errorf("generate key pair: %w", err))
	}

	// Build the CIC exactly as the OpenPubkey client does: a JWK of the public
	// key with the algorithm set, wrapped in client instance claims.
	jwkKey, err := jwk.PublicKeyOf(signer.Public())
	if err != nil {
		return fail(fmt.Errorf("jwk from public key: %w", err))
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, alg); err != nil {
		return fail(fmt.Errorf("set alg on jwk: %w", err))
	}
	cic, err := clientinstance.NewClaims(jwkKey, map[string]any{})
	if err != nil {
		return fail(fmt.Errorf("new client instance claims: %w", err))
	}

	// The nonce is the CIC hash; placing it in the OIDC nonce commits the
	// ephemeral public key inside the OP-signed ID token.
	nonce, err := cic.Hash()
	if err != nil {
		return fail(fmt.Errorf("hash client instance claims: %w", err))
	}

	mu.Lock()
	seq++
	sid := fmt.Sprintf("s%d", seq)
	sessions[sid] = &session{signer: signer, cic: cic}
	mu.Unlock()

	return ok(map[string]any{"sid": sid, "nonce": string(nonce)})
}

// assemble(sid, idToken) -> {ok, pkt, privateJwk} signs the CIC over the
// OP-signed ID token and returns the serialized PK Token together with the
// ephemeral private key (JWK) so the wallet can persist it for later
// proof-of-possession. The session is consumed on success.
func assemble(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return fail(fmt.Errorf("assemble requires (sid, idToken)"))
	}
	sid := args[0].String()
	idToken := []byte(args[1].String())

	mu.Lock()
	s := sessions[sid]
	mu.Unlock()
	if s == nil {
		return fail(fmt.Errorf("unknown or expired session %q", sid))
	}

	// Sign the ID token payload with the CIC protected headers, then combine
	// into a PK Token (ID token signature + user's CIC signature).
	cicToken, err := s.cic.Sign(s.signer, alg, idToken)
	if err != nil {
		return fail(fmt.Errorf("sign cic: %w", err))
	}
	pkt, err := pktoken.New(idToken, cicToken)
	if err != nil {
		return fail(fmt.Errorf("new pk token: %w", err))
	}
	pktJSON, err := pkt.MarshalJSON()
	if err != nil {
		return fail(fmt.Errorf("marshal pk token: %w", err))
	}

	// Export the ephemeral private key as a JWK for persistence (A1). In this
	// milestone the key is stored by the JS side; hardening it to a
	// non-extractable WebCrypto key is a follow-up.
	privJWK, err := jwk.Import(s.signer)
	if err != nil {
		return fail(fmt.Errorf("import private key to jwk: %w", err))
	}
	if err := privJWK.Set(jwk.AlgorithmKey, alg); err != nil {
		return fail(fmt.Errorf("set alg on private jwk: %w", err))
	}
	privJSON, err := json.Marshal(privJWK)
	if err != nil {
		return fail(fmt.Errorf("marshal private jwk: %w", err))
	}

	mu.Lock()
	delete(sessions, sid)
	mu.Unlock()

	return ok(map[string]any{"pkt": string(pktJSON), "privateJwk": string(privJSON)})
}

// signChallenge(privateJwk, pkt, challenge) -> {ok, osm} signs a Verifier's
// challenge with the ephemeral private key committed in the given PK Token,
// producing an OpenPubkey signed message (the proof-of-possession).
func signChallenge(this js.Value, args []js.Value) any {
	if len(args) < 3 {
		return fail(fmt.Errorf("signChallenge requires (privateJwk, pkt, challenge)"))
	}
	privateJwk := []byte(args[0].String())
	pktJSON := []byte(args[1].String())
	challenge := []byte(args[2].String())

	key, err := jwk.ParseKey(privateJwk)
	if err != nil {
		return fail(fmt.Errorf("parse private jwk: %w", err))
	}
	var priv ecdsa.PrivateKey
	if err := jwk.Export(key, &priv); err != nil {
		return fail(fmt.Errorf("export private key: %w", err))
	}

	var pkt pktoken.PKToken
	if err := json.Unmarshal(pktJSON, &pkt); err != nil {
		return fail(fmt.Errorf("parse pk token: %w", err))
	}

	osm, err := pkt.NewSignedMessage(challenge, &priv)
	if err != nil {
		return fail(fmt.Errorf("sign challenge: %w", err))
	}
	return ok(map[string]any{"osm": string(osm)})
}
