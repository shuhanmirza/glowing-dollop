package main

// Blind-relay login (split-PKCE).
//
// When the user's namespace domain declares a blind relay (see byoid.go) and
// the Verifier has no binding with the declared issuer, the Verifier signs the
// user in through the relay WITHOUT trusting it with the token:
//
//  1. /api/relay/start: the Verifier discovers the domain's relay + issuer,
//     OIDC-discovers the issuer, generates PKCE (code_verifier kept here) and a
//     nonce, and redirects the browser to the OP. The OP's registered redirect
//     URI is the relay's callback; the OAuth `state` carries the Verifier's own
//     callback so the relay knows where to relay the code.
//  2. The OP sends the code to the relay; the relay forwards it to
//     /api/relay/callback (it cannot redeem it — it has no code_verifier).
//  3. /api/relay/callback: the Verifier redeems the code itself (public client,
//     PKCE, no secret), verifies the ID token (signature via the issuer's JWKS,
//     audience, issuer, nonce), and requires the token email to match the
//     entered email and its domain to equal the declared namespace.
//
// The relay never sees the token (blind), and the Verifier redeems its own code
// (the one-shot redeem model), so no proof-of-possession is required.

import (
	"context"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// relayPending is the per-flow state stored at start and consumed at callback.
type relayPending struct {
	email    string
	domain   string
	issuer   string
	clientID string
	verifier string // PKCE code_verifier (held by the Verifier, never the relay)
	nonce    string
	redirect string // exact redirect_uri used (relay /cb) — must match on exchange
	created  time.Time
}

var (
	relayMu       sync.Mutex
	relayFlows    = map[string]*relayPending{}
	oidcProvCache = map[string]*oidc.Provider{}
)

// gcRelayFlows drops expired flows. Caller must hold relayMu.
func gcRelayFlows() {
	now := time.Now()
	for k, v := range relayFlows {
		if now.Sub(v.created) > stateTTL {
			delete(relayFlows, k)
		}
	}
}

// oidcProviderFor discovers (and caches) the OIDC provider for an issuer.
func oidcProviderFor(ctx context.Context, issuer string) (*oidc.Provider, error) {
	relayMu.Lock()
	if p := oidcProvCache[issuer]; p != nil {
		relayMu.Unlock()
		return p, nil
	}
	relayMu.Unlock()

	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	relayMu.Lock()
	oidcProvCache[issuer] = p
	relayMu.Unlock()
	return p, nil
}

// relayState is the subset of the signed routing state the callback needs. The
// wire form is a compact ES256 JWS (see jar.go); the relay verifies it against
// the Verifier's published JWKS before relaying. `cb` is where the relay forwards
// the code, `sid` is our flow lookup key, `step` selects the step-by-step demo.
type relayState struct {
	CB   string
	SID  string
	Step bool
}

// decodeRelayState verifies a routing-state JWS we signed and returns the
// subset the callback needs. The sid->store lookup remains the real authority;
// verifying the signature here is defence in depth against a tampered state.
func decodeRelayState(raw string) (*relayState, error) {
	claims, err := verifyOwnRoutingState(raw)
	if err != nil {
		return nil, err
	}
	return &relayState{CB: claims.CB, SID: claims.SID, Step: claims.Step}, nil
}

// relayCallbackURL is the Verifier callback the relay forwards the code to. It
// must be same-origin as the JWS issuer (verifierOrigin) so the relay can bind
// "who signed this request" to "where the code is allowed to go".
func relayCallbackURL() string {
	return verifierOrigin() + "/api/relay/callback"
}

// handleRelayStart begins the split-PKCE flow and redirects the browser to the
// OP (via the relay's registered redirect URI).
func handleRelayStart(c *gin.Context) {
	ctx := c.Request.Context()

	email, ok := normalizeEmail(c.Query("email"))
	if !ok {
		redirectFrontendError(c, "invalid_email")
		return
	}
	domain := email[strings.LastIndex(email, "@")+1:]

	cfg, ok := discoverByoidConfig(ctx, domain)
	if !ok || !cfg.hasRelayDelegation() {
		redirectFrontendError(c, "no_relay")
		return
	}

	provider, err := oidcProviderFor(ctx, cfg.Issuer)
	if err != nil {
		redirectFrontendError(c, "issuer_unavailable")
		return
	}

	sid, e1 := randomToken(24)
	nonce, e2 := randomToken(32)
	verifier, e3 := randomToken(48)
	if e1 != nil || e2 != nil || e3 != nil {
		redirectFrontendError(c, "server_error")
		return
	}

	redirect := cfg.RelayRedirectURI
	scopes := cfg.Scopes
	if scopes == "" {
		scopes = "openid email"
	}
	step := c.Query("step") == "1"

	relayMu.Lock()
	gcRelayFlows()
	relayFlows[sid] = &relayPending{
		email: email, domain: domain, issuer: cfg.Issuer, clientID: cfg.ClientID,
		verifier: verifier, nonce: nonce, redirect: redirect, created: time.Now(),
	}
	relayMu.Unlock()

	jti, err := newJTI()
	if err != nil {
		redirectFrontendError(c, "server_error")
		return
	}
	now := nowUnix()
	claims := routingClaims{
		Aud:   relayOrigin(),
		CB:    relayCallbackURL(),
		SID:   sid,
		Step:  step,
		OP:    cfg.Issuer,
		Scope: scopes,
		JTI:   jti,
		IAT:   now,
		EXP:   now + int64(routingStateTTL.Seconds()),
	}
	state, err := signRoutingState(claims)
	if err != nil {
		redirectFrontendError(c, "server_error")
		return
	}

	challenge := pkceChallenge(verifier)
	conf := &oauth2.Config{
		ClientID:    cfg.ClientID, // public client, no secret
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirect,
		Scopes:      strings.Fields(scopes),
	}
	authURL := conf.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	log.Printf("[BYOID:verifier] relay flow start: email=%s issuer=%s relay=%s (sid=%s, step=%v)",
		email, cfg.Issuer, cfg.RelayRedirectURI, sid, step)

	if step {
		// Step-by-step: show the OP authorization request before sending it.
		renderStepPage(c, stepView{
			Actor:    "xyz.com · Verifier",
			Progress: "Step 1 of 4",
			Title:    "The Verifier builds the OIDC request",
			Subtitle: template.HTML("No pre-registration with the OP. The Verifier sends a standard " +
				"authorization-code + PKCE request, but points <code>redirect_uri</code> at the " +
				"<strong>blind relay</strong> and keeps the PKCE <code>code_verifier</code> to itself."),
			Blocks: []stepBlock{
				{
					Heading: "Authorization request → " + provider.Endpoint().AuthURL,
					Rows: []stepRow{
						{K: "client_id", V: cfg.ClientID, Mono: true},
						{K: "redirect_uri", V: redirect, Mono: true, Note: "the relay's callback — not xyz.com"},
						{K: "response_type", V: "code", Mono: true},
						{K: "scope", V: scopes, Mono: true},
						{K: "code_challenge", V: challenge, Mono: true, Note: "S256(code_verifier) — the verifier stays at xyz.com"},
						{K: "code_challenge_method", V: "S256", Mono: true},
						{K: "nonce", V: nonce, Mono: true},
					},
				},
				{
					Heading: "state — a signed JWT (ES256), verified by the relay against xyz.localhost's JWKS",
					Code:    prettyJSON(claims),
				},
			},
			NextURL:   authURL,
			NextLabel: "Send to the OP →",
			NextNote:  "You'll authenticate at the OP, then the OP returns the code to the blind relay.",
		})
		return
	}
	c.Redirect(http.StatusFound, authURL)
}

// prettyJSON marshals v as indented JSON for display in a step page.
func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

// handleRelayCallback is where the relay forwards the code. The Verifier redeems
// it here (public client + PKCE, no secret) and verifies the ID token.
func handleRelayCallback(c *gin.Context) {
	ctx := c.Request.Context()

	if e := c.Query("error"); e != "" {
		redirectFrontendError(c, e)
		return
	}
	rawState, code := c.Query("state"), c.Query("code")
	if rawState == "" || code == "" {
		redirectFrontendError(c, "invalid_response")
		return
	}
	st, err := decodeRelayState(rawState)
	if err != nil {
		redirectFrontendError(c, "invalid_state")
		return
	}

	// In step-by-step mode the first arrival (no phase) pauses to show the token
	// request the Verifier is about to send; "phase=exchange" then performs it.
	// Only consume the pending flow when we actually redeem.
	showPayload := st.Step && c.Query("phase") != "exchange"

	relayMu.Lock()
	p := relayFlows[st.SID]
	if p != nil && !showPayload {
		delete(relayFlows, st.SID)
	}
	relayMu.Unlock()
	if p == nil || time.Since(p.created) > stateTTL {
		redirectFrontendError(c, "expired")
		return
	}

	provider, err := oidcProviderFor(ctx, p.issuer)
	if err != nil {
		redirectFrontendError(c, "issuer_unavailable")
		return
	}

	if showPayload {
		// Step 3: show the token request the Verifier will send to the OP. It
		// holds the code_verifier the relay never had, so only it can redeem.
		next := url.Values{}
		next.Set("code", code)
		next.Set("state", rawState)
		next.Set("phase", "exchange")
		renderStepPage(c, stepView{
			Actor:    "xyz.com · Verifier",
			Progress: "Step 3 of 4",
			Title:    "The Verifier redeems the code",
			Subtitle: template.HTML("The blind relay relayed the code but could not use it. The Verifier " +
				"now exchanges it at the OP's token endpoint using the PKCE " +
				"<code>code_verifier</code> only it holds — no client secret (public client)."),
			Blocks: []stepBlock{
				{
					Heading: "Token request → " + provider.Endpoint().TokenURL,
					Rows: []stepRow{
						{K: "grant_type", V: "authorization_code", Mono: true},
						{K: "client_id", V: p.clientID, Mono: true},
						{K: "code", V: code, Mono: true, Note: "relayed by the blind relay"},
						{K: "code_verifier", V: p.verifier, Mono: true, Note: "the PKCE secret the relay never saw"},
						{K: "redirect_uri", V: p.redirect, Mono: true},
						{K: "client_secret", V: "(none)", Note: "public client"},
					},
				},
			},
			NextURL:   relayCallbackURL() + "?" + next.Encode(),
			NextLabel: "Exchange the code →",
			NextNote:  "The Verifier calls the OP token endpoint and receives the ID token.",
		})
		return
	}

	conf := &oauth2.Config{
		ClientID:    p.clientID, // public client, no secret
		Endpoint:    provider.Endpoint(),
		RedirectURL: p.redirect,
	}
	tok, err := conf.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", p.verifier))
	if err != nil {
		log.Printf("[BYOID:verifier] relay token exchange failed (sid=%s): %v", st.SID, err)
		redirectFrontendError(c, "exchange_failed")
		return
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		redirectFrontendError(c, "no_id_token")
		return
	}

	idToken, err := provider.Verifier(&oidc.Config{ClientID: p.clientID}).Verify(ctx, rawID)
	if err != nil {
		redirectFrontendError(c, "invalid_id_token")
		return
	}
	if idToken.Nonce != p.nonce {
		redirectFrontendError(c, "nonce_mismatch")
		return
	}

	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	_ = idToken.Claims(&claims)

	// The token's email must equal the email being authenticated, and its
	// domain must equal the declared namespace. This is the demo's membership
	// check (the OP has no org-restricted client concept).
	tokenEmail := strings.ToLower(strings.TrimSpace(claims.Email))
	if tokenEmail != p.email {
		redirectFrontendError(c, "email_mismatch")
		return
	}
	tokenDomain := ""
	if i := strings.LastIndex(tokenEmail, "@"); i >= 0 {
		tokenDomain = tokenEmail[i+1:]
	}
	if tokenDomain != p.domain {
		redirectFrontendError(c, "namespace_mismatch")
		return
	}

	log.Printf("[BYOID:verifier] relay flow OK: %s via issuer %s (relay was blind)", tokenEmail, idToken.Issuer)

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
		Provider:      "relay",
		created:       time.Now(),
	}
	storeMu.Unlock()

	successURL := frontendURL() + "/?login=" + id

	if st.Step {
		// Step 4: show the token the Verifier received before landing on success.
		var allClaims map[string]any
		_ = idToken.Claims(&allClaims)
		renderStepPage(c, stepView{
			Actor:    "xyz.com · Verifier",
			Progress: "Step 4 of 4",
			Title:    "The Verifier received the ID token",
			Subtitle: template.HTML("The OP returned a signed ID token. The Verifier checked the " +
				"signature against the issuer's JWKS, the audience, the nonce, and that the email is " +
				"within the declared namespace. The blind relay never saw any of this."),
			Blocks: []stepBlock{
				{
					Heading: "Checks passed",
					Rows: []stepRow{
						{K: "signature", V: "✓ verified", Note: "against " + idToken.Issuer + " JWKS"},
						{K: "issuer", V: idToken.Issuer, Mono: true},
						{K: "audience", V: p.clientID, Mono: true},
						{K: "nonce", V: "✓ matches", Note: "bound to this session"},
						{K: "email / namespace", V: "✓ " + tokenEmail, Note: "within " + p.domain},
					},
				},
				{Heading: "ID token — decoded claims", Code: prettyJSON(allClaims)},
				{Heading: "ID token — raw JWS (header.payload.signature)", Code: rawID},
			},
			NextURL:   successURL,
			NextLabel: "Finish sign-in →",
			NextNote:  "The Verifier issues its own session; the OP token is discarded (one-shot).",
		})
		return
	}

	c.Redirect(http.StatusFound, successURL)
}
