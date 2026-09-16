package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenderConsent exercises the consent template in both normal and
// step-by-step modes to catch template-execution errors (which the compiler
// cannot see) and to confirm the security-relevant facts are shown.
func TestRenderConsent(t *testing.T) {
	claims := &routingClaims{
		CB:    "http://xyz.localhost:11110/api/relay/callback",
		OP:    "http://op.localhost:5556",
		Scope: "openid email profile",
		SID:   "sid-demo-1",
		JTI:   "jti-demo-1",
		IAT:   1700000000,
		EXP:   1700000300,
	}

	t.Run("normal", func(t *testing.T) {
		rec := httptest.NewRecorder()
		renderConsent(rec, claims, "AUTHCODE-XYZ", "SIGNED-STATE")
		body := rec.Body.String()
		for _, want := range []string{
			"xyz.localhost:11110",         // where the code is relayed
			"op.localhost:5556",           // which OP authenticated
			"your email address",          // scope meaning
			"action=\"/relay\"",           // consent posts to /relay
			"value=\"allow\"",             // continue decision
			"value=\"deny\"",              // cancel decision
			"SIGNED-STATE",                // state echoed in the form
			"Request signature verified",  // verified panel present
			"/.well-known/byoid-verifier", // shows the JWKS source
			"xyz.localhost",               // signer host in the panel
			"Signed state (decoded",       // decoded-state block present
			"sid-demo-1",                  // a spelled-out claim value
			"single-use id",               // jti note in the state block
		} {
			if !strings.Contains(body, want) {
				t.Errorf("consent page missing %q", want)
			}
		}
		// Normal mode does not show the technical "Step 2 of 4" detail block.
		if strings.Contains(body, "Step 2 of 4") {
			t.Error("normal mode should not show the step-by-step progress label")
		}
	})

	t.Run("step", func(t *testing.T) {
		sc := *claims
		sc.Step = true
		rec := httptest.NewRecorder()
		renderConsent(rec, &sc, "AUTHCODE-XYZ", "SIGNED-STATE")
		body := rec.Body.String()
		for _, want := range []string{"Step 2 of 4", "AUTHCODE-XYZ", "api/relay/callback"} {
			if !strings.Contains(body, want) {
				t.Errorf("step consent page missing %q", want)
			}
		}
	})
}
