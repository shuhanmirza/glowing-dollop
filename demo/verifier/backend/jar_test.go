package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
)

// TestRoutingStateRoundTrip signs a routing state and verifies it with our own
// public key (the defence-in-depth path used at the callback).
func TestRoutingStateRoundTrip(t *testing.T) {
	now := nowUnix()
	in := routingClaims{
		Aud: relayOrigin(),
		CB:  verifierOrigin() + "/api/relay/callback", SID: "sid-xyz",
		Step: true, OP: "http://op.localhost:5556", Scope: "openid email",
		JTI: "jti-1", IAT: now, EXP: now + 300,
	}
	tok, err := signRoutingState(in)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	out, err := verifyOwnRoutingState(tok)
	if err != nil {
		t.Fatalf("verify own: %v", err)
	}
	if out.SID != in.SID || out.CB != in.CB || out.OP != in.OP || out.Step != in.Step {
		t.Fatalf("round-trip mismatch: %+v vs %+v", out, in)
	}
}

// TestVerifierJWKSEndpoint checks the published JWKS contains an ES256 sig key
// whose kid matches the one used to sign, so the relay can find it.
func TestVerifierJWKSEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	handleVerifierJWKS(c)

	if rec.Code != 200 {
		t.Fatalf("status = %d", rec.Code)
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("decode jwks: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("want 1 key, got %d", len(set.Keys))
	}
	k := set.Keys[0]
	if k.Algorithm != string(jose.ES256) || k.Use != "sig" || k.KeyID == "" {
		t.Fatalf("unexpected jwk: alg=%s use=%s kid=%q", k.Algorithm, k.Use, k.KeyID)
	}
	// The kid must match what signRoutingState stamps, or the relay can't
	// locate the key by kid.
	_, kid := jarSigningKey()
	if k.KeyID != kid {
		t.Fatalf("jwks kid %q != signing kid %q", k.KeyID, kid)
	}
}
