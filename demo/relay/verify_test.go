package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// signer bundles an ES256 key with an httptest server publishing its JWKS at
// /.well-known/byoid-verifier, standing in for a Verifier.
type signer struct {
	key    *ecdsa.PrivateKey
	kid    string
	server *httptest.Server
}

func newSigner(t *testing.T) *signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &signer{key: k, kid: "test-kid-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/byoid-verifier", func(w http.ResponseWriter, r *http.Request) {
		jwk := jose.JSONWebKey{Key: k.Public(), KeyID: s.kid, Algorithm: string(jose.ES256), Use: "sig"}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
	})
	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// sign issues a compact ES256 JWS with the routing typ header.
func (s *signer) sign(t *testing.T, c routingClaims) string {
	t.Helper()
	payload, _ := json.Marshal(c)
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(routingStateTyp)).
		WithHeader("kid", s.kid)
	jw, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	obj, err := jw.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	compact, err := obj.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return compact
}

// validClaims builds a well-formed routing state for signer s.
func (s *signer) validClaims() routingClaims {
	now := time.Now().Unix()
	iss := s.server.URL // http://127.0.0.1:PORT
	return routingClaims{
		Aud:   relayOrigin(),
		CB:    iss + "/api/relay/callback",
		SID:   "sid-1",
		OP:    "http://op.localhost:5556",
		Scope: "openid email",
		JTI:   "jti-" + iss,
		IAT:   now,
		EXP:   now + 300,
	}
}

// setEnv makes the relay accept 127.0.0.1 JWKS hosts and expect the right aud.
func setEnv(t *testing.T) {
	t.Helper()
	t.Setenv("RELAY_ORIGIN", "http://relayoidc.localhost:9090")
	t.Setenv("VERIFIER_ALLOWED_HOSTS", "127.0.0.1,localhost")
	// Reset caches between tests so allowlist/env changes take effect.
	jwksMu.Lock()
	jwksCache = map[string]cachedKeys{}
	jwksMu.Unlock()
	jtiMu.Lock()
	jtiSeen = map[string]int64{}
	jtiMu.Unlock()
}

func TestVerifyRoutingState_OK(t *testing.T) {
	setEnv(t)
	s := newSigner(t)
	tok := s.sign(t, s.validClaims())

	claims, err := verifyRoutingState(tok, false)
	if err != nil {
		t.Fatalf("valid state rejected: %v", err)
	}
	if claims.SID != "sid-1" || claims.OP == "" {
		t.Fatalf("claims not returned: %+v", claims)
	}
}

func TestVerifyRoutingState_Failures(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(c *routingClaims)
		tamper bool // flip a payload byte after signing
	}{
		{name: "expired", mutate: func(c *routingClaims) { c.EXP = time.Now().Unix() - 1 }},
		{name: "wrong aud", mutate: func(c *routingClaims) { c.Aud = "http://evil.example:9090" }},
		// Key is fetched from the CB origin; a bogus/unresolvable callback host
		// means there is no JWKS to verify against, so the state is rejected.
		{name: "cb host has no jwks", mutate: func(c *routingClaims) { c.CB = "http://evil.invalid/api/relay/callback" }},
		{name: "tampered signature", tamper: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t)
			s := newSigner(t)
			c := s.validClaims()
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			tok := s.sign(t, c)
			if tc.tamper {
				b := []byte(tok)
				b[len(b)-3] ^= 0x01 // corrupt the signature segment
				tok = string(b)
			}
			if _, err := verifyRoutingState(tok, false); err == nil {
				t.Fatalf("%s: expected rejection, got success", tc.name)
			}
		})
	}
}

func TestVerifyRoutingState_ReplayJTI(t *testing.T) {
	setEnv(t)
	s := newSigner(t)
	tok := s.sign(t, s.validClaims())

	if _, err := verifyRoutingState(tok, true); err != nil {
		t.Fatalf("first consume failed: %v", err)
	}
	if _, err := verifyRoutingState(tok, true); err == nil {
		t.Fatal("replay of consumed jti should be rejected")
	}
	// A non-consuming verify (consent GET) must stay idempotent before consume.
	setEnv(t) // reset caches
	s2 := newSigner(t)
	tok2 := s2.sign(t, s2.validClaims())
	if _, err := verifyRoutingState(tok2, false); err != nil {
		t.Fatalf("non-consuming verify failed: %v", err)
	}
	if _, err := verifyRoutingState(tok2, false); err != nil {
		t.Fatalf("second non-consuming verify should still pass: %v", err)
	}
}

func TestVerifyRoutingState_WrongTyp(t *testing.T) {
	setEnv(t)
	s := newSigner(t)
	// Sign without the routing typ header.
	payload, _ := json.Marshal(s.validClaims())
	jw, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: s.key},
		(&jose.SignerOptions{}).WithHeader("kid", s.kid))
	obj, _ := jw.Sign(payload)
	tok, _ := obj.CompactSerialize()
	if _, err := verifyRoutingState(tok, false); err == nil {
		t.Fatal("state without byoid-routing typ should be rejected")
	}
}

func TestGuardSSRF(t *testing.T) {
	t.Setenv("VERIFIER_ALLOWED_HOSTS", "xyz.localhost,localhost,127.0.0.1")
	// Allowlisted loopback host passes.
	if err := guardSSRF("xyz.localhost"); err != nil {
		t.Fatalf("allowlisted host blocked: %v", err)
	}
	// A public-DNS name that resolves to a private/link-local address must be
	// blocked. 169.254.169.254 (cloud metadata) is link-local; use a literal.
	if err := guardSSRF("169.254.169.254"); err == nil {
		t.Fatal("link-local metadata address should be blocked")
	}
	if err := guardSSRF("10.0.0.5"); err == nil {
		t.Fatal("private address should be blocked")
	}
}
