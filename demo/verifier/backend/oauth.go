package main

// Google OAuth / OIDC login for the demo Verifier.
//
// This implements the case where the Verifier already has a client binding with
// an OpenID Provider (here, Google) and the user's email belongs to a domain
// served by that provider (e.g. gmail.com). The user is sent through a standard
// OpenID Connect authorization-code flow (with PKCE); the returned ID token is
// verified (signature via the provider's JWKS, audience, issuer, and the nonce
// we committed) and its email claim is surfaced as the signed-in identity.
//
// The OAuth client is OpenPubkey's public Google client (see providers/google.go
// in github.com/openpubkey/openpubkey). Its credentials are intentionally
// published by that project — Google requires a client secret even for this
// "installed app" style client — so the demo can run a real Google login
// without registering our own client. Google enforces an exact redirect-URI
// match for this client, so the callback must be served at one of its
// registered loopback URIs (localhost:{3000,10001,11110}/login-callback); the
// demo backend therefore listens on port 11110 and serves /login-callback.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// OpenPubkey's public Google OAuth client (intentionally published).
const (
	googleClientID     = "206584157355-7cbe4s640tvm7naoludob4ut1emii7sf.apps.googleusercontent.com"
	googleClientSecret = "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"
	googleIssuer       = "https://accounts.google.com"
	googleCallbackPath = "/login-callback"
)

// stateTTL bounds how long a started login may take to complete.
const stateTTL = 10 * time.Minute

// googleRedirectURL is the exact redirect URI registered for the OpenPubkey
// Google client. It must match one of the registered loopback URIs
// (localhost:{3000,10001,11110}/login-callback). We default to 11110 because
// 3000 collides with common dev servers.
func googleRedirectURL() string {
	if v := os.Getenv("GOOGLE_REDIRECT_URL"); v != "" {
		return v
	}
	return "http://localhost:11110" + googleCallbackPath
}

// frontendURL is where the user is redirected back to after the round-trip.
func frontendURL() string {
	if v := os.Getenv("FRONTEND_URL"); v != "" {
		return v
	}
	return "http://localhost:5173"
}

// oidcClients lazily initializes the OIDC provider (discovery) and verifier.
// Initialization needs network access to Google, so it is done on first use
// rather than at startup; failures are retried on the next request.
var (
	oidcMu       sync.Mutex
	oidcProvider *oidc.Provider
	oidcVerifier *oidc.IDTokenVerifier
)

func oidcClients(ctx context.Context) (*oidc.Provider, *oidc.IDTokenVerifier, error) {
	oidcMu.Lock()
	defer oidcMu.Unlock()
	if oidcProvider != nil {
		return oidcProvider, oidcVerifier, nil
	}
	p, err := oidc.NewProvider(ctx, googleIssuer)
	if err != nil {
		return nil, nil, err
	}
	oidcProvider = p
	oidcVerifier = p.Verifier(&oidc.Config{ClientID: googleClientID})
	return oidcProvider, oidcVerifier, nil
}

func oauthConfig(p *oidc.Provider) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     googleClientID,
		ClientSecret: googleClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  googleRedirectURL(),
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
}

// pendingLogin is the per-request state created at start and consumed at the
// callback. nonce binds the ID token to this request; verifier is the PKCE
// code_verifier.
type pendingLogin struct {
	nonce    string
	verifier string
	created  time.Time
}

// loginResult is the verified identity, fetched once by the frontend.
type loginResult struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
	Subject       string `json:"sub"`
	Issuer        string `json:"iss"`
	Provider      string `json:"provider"`
	created       time.Time
}

var (
	storeMu sync.Mutex
	pending = map[string]*pendingLogin{}
	results = map[string]*loginResult{}
)

// gcStore drops expired entries. Caller must hold storeMu.
func gcStore() {
	now := time.Now()
	for k, v := range pending {
		if now.Sub(v.created) > stateTTL {
			delete(pending, k)
		}
	}
	for k, v := range results {
		if now.Sub(v.created) > stateTTL {
			delete(results, k)
		}
	}
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// handleGoogleStart begins the authorization-code flow (with PKCE) and redirects
// the browser to Google's consent screen.
func handleGoogleStart(c *gin.Context) {
	ctx := c.Request.Context()
	provider, _, err := oidcClients(ctx)
	if err != nil {
		redirectFrontendError(c, "google_unavailable")
		return
	}

	state, e1 := randomToken(32)
	nonce, e2 := randomToken(32)
	verifier, e3 := randomToken(48)
	if e1 != nil || e2 != nil || e3 != nil {
		redirectFrontendError(c, "server_error")
		return
	}

	storeMu.Lock()
	gcStore()
	pending[state] = &pendingLogin{nonce: nonce, verifier: verifier, created: time.Now()}
	storeMu.Unlock()

	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", pkceChallenge(verifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	if hint := c.Query("email"); hint != "" {
		opts = append(opts, oauth2.SetAuthURLParam("login_hint", hint))
	}
	c.Redirect(http.StatusFound, oauthConfig(provider).AuthCodeURL(state, opts...))
}

// handleGoogleCallback exchanges the code, verifies the ID token, stores the
// result, and sends the user back to the frontend.
func handleGoogleCallback(c *gin.Context) {
	ctx := c.Request.Context()

	if e := c.Query("error"); e != "" {
		redirectFrontendError(c, e)
		return
	}
	state, code := c.Query("state"), c.Query("code")
	if state == "" || code == "" {
		redirectFrontendError(c, "invalid_response")
		return
	}

	storeMu.Lock()
	p := pending[state]
	delete(pending, state)
	storeMu.Unlock()
	if p == nil || time.Since(p.created) > stateTTL {
		redirectFrontendError(c, "expired")
		return
	}

	provider, verifier, err := oidcClients(ctx)
	if err != nil {
		redirectFrontendError(c, "google_unavailable")
		return
	}

	tok, err := oauthConfig(provider).Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", p.verifier))
	if err != nil {
		redirectFrontendError(c, "exchange_failed")
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		redirectFrontendError(c, "no_id_token")
		return
	}

	// Demo visibility: log what Google returned from the token endpoint. This
	// is what the Verifier receives in exchange for the authorization code. We
	// log the metadata (not the raw access/ID token strings). A production
	// Verifier would not log any of this.
	log.Printf("[google] token endpoint response: token_type=%s expires_in≈%s scope=%v refresh_token_present=%t id_token_present=%t",
		tok.TokenType, time.Until(tok.Expiry).Round(time.Second), tok.Extra("scope"), tok.RefreshToken != "", rawID != "")

	idToken, err := verifier.Verify(ctx, rawID)
	if err != nil {
		redirectFrontendError(c, "invalid_id_token")
		return
	}
	if idToken.Nonce != p.nonce {
		redirectFrontendError(c, "nonce_mismatch")
		return
	}

	// Demo visibility: log every claim in the verified ID token. These claims
	// are exactly the knowledge Google shared with the Verifier about the user.
	var allClaims map[string]any
	if err := idToken.Claims(&allClaims); err == nil {
		if pretty, e := json.MarshalIndent(allClaims, "", "  "); e == nil {
			log.Printf("[google] verified ID token claims (what Google told the Verifier about the user):\n%s", pretty)
		}
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	_ = idToken.Claims(&claims)

	id, err := randomToken(24)
	if err != nil {
		redirectFrontendError(c, "server_error")
		return
	}
	storeMu.Lock()
	gcStore()
	results[id] = &loginResult{
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
		Subject:       idToken.Subject,
		Issuer:        idToken.Issuer,
		Provider:      "google",
		created:       time.Now(),
	}
	storeMu.Unlock()

	c.Redirect(http.StatusFound, frontendURL()+"/?login="+id)
}

// handleLoginResult returns the verified identity once, then discards it.
func handleLoginResult(c *gin.Context) {
	id := c.Query("id")
	storeMu.Lock()
	r := results[id]
	delete(results, id)
	storeMu.Unlock()
	if r == nil {
		c.JSON(http.StatusNotFound, errorResponse{Error: "login result not found or already used"})
		return
	}
	c.JSON(http.StatusOK, r)
}

func redirectFrontendError(c *gin.Context, code string) {
	c.Redirect(http.StatusFound, frontendURL()+"/?login_error="+code)
}
