package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

// TestRenderStepPage exercises the step interstitial template with all branches
// (rows + a code block + an HTML subtitle) to catch template execution errors,
// which the compiler and go vet cannot see.
func TestRenderStepPage(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)

	renderStepPage(c, stepView{
		Actor:    "xyz.com · Verifier",
		Progress: "Step 3 of 4",
		Title:    "Verifier redeems the code",
		Subtitle: "The Verifier holds the <b>code_verifier</b>.",
		Blocks: []stepBlock{
			{
				Heading: "POST token request",
				Rows: []stepRow{
					{K: "client_id", V: "byoid-relay-client"},
					{K: "code_verifier", V: "abc123", Note: "the relay never saw this", Mono: true},
				},
			},
			{Heading: "Decoded state", Code: "{\n  \"cb\": \"http://x/cb\"\n}"},
		},
		NextURL:   "/api/relay/callback?phase=exchange&sid=s1",
		NextLabel: "Exchange the code →",
		NextNote:  "The Verifier calls the OP token endpoint.",
	})

	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	for _, want := range []string{
		"Step 3 of 4",
		"Verifier redeems the code",
		"<b>code_verifier</b>", // Subtitle rendered as HTML, not escaped
		"byoid-relay-client",
		"the relay never saw this",
		"phase=exchange",
		"Exchange the code →",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("rendered page missing %q", want)
		}
	}
}
