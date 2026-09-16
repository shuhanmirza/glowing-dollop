// Command backend is the Verifier's API server for the Bring-Your-Own-IdP demo.
//
// The Verifier is the Relying Party (SP) that wants to authenticate a user. The
// sign-in flow is identifier-first: the user submits their email, and the
// backend decides how to authenticate them (POST /api/login/start):
//
//   - "password": the user has a local username/password account with the
//     Verifier itself (POST /api/login/password).
//   - "oauth":    the user's domain is served by a provider the Verifier has a
//     client binding with (Google); sign in via OpenID Connect (see oauth.go).
//   - "trust":    with no pre-binding, the namespace domain declares an
//     authorized issuer via WebFinger over HTTPS, so the Verifier can trust the
//     domain->issuer relationship (see webfinger.go). The issuer (OP) is never
//     asked to declare anything and stays unmodified.
//   - "ebia":     no trusted domain->issuer relationship; fall back to proving
//     mailbox control via a magic link (see ebia.go).
//
// No database is involved; demo accounts and bindings are hard-coded (see
// accounts.go), and challenge state is kept in memory.
package main

import (
	"crypto/subtle"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// emailRe is a deliberately permissive email check. We only need enough
// structure to extract a domain; strict RFC 5322 validation is out of scope.
var emailRe = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)

// loginStartRequest is the payload posted when the user submits their email.
type loginStartRequest struct {
	Email string `json:"email"`
}

// loginStartResponse tells the frontend how to authenticate this user. Method
// is one of:
//
//   - "password": prompt for a local password (POST /api/login/password)
//   - "oauth":    start an OIDC flow with Provider (GET /api/oauth/<p>/start);
//     the domain->issuer trust is known from a provider binding.
//   - "trust":    the Verifier established a trusted domain->issuer relationship
//     via the domain's WebFinger declaration; the user completes sign-in by
//     proving possession of a PK Token from that issuer with their identity
//     wallet (see wallet.go).
//   - "ebia":     no trusted domain->issuer relationship could be established;
//     fall back to proving mailbox control via a magic link.
type loginStartResponse struct {
	Email    string     `json:"email"`
	Domain   string     `json:"domain"`
	Method   string     `json:"method"`
	Provider string     `json:"provider,omitempty"`
	Trust    *trustInfo `json:"trust,omitempty"`
	EBIA     *ebiaInfo  `json:"ebia,omitempty"`
	Relay    *relayInfo `json:"relay,omitempty"`
}

// relayInfo describes a blind-relay delegation the namespace domain declared,
// shown to the user before they continue through the blind relay.
type relayInfo struct {
	Namespace        string `json:"namespace"`
	Issuer           string `json:"issuer"`
	RelayRedirectURI string `json:"relay_redirect_uri"`
	// WellKnown is the exact /.well-known/byoid-configuration document the
	// Verifier fetched, so the UI can show it in a "Details" panel.
	WellKnown string `json:"wellKnown,omitempty"`
}

// trustInfo describes an established domain->issuer relationship, shown to the
// user as a trust cue. Source is how it was established:
//
//   - "webfinger":      the namespace domain declared the issuer over HTTPS.
//   - "known-provider": the Verifier already has a binding with this provider.
type trustInfo struct {
	Established bool   `json:"established"`
	Domain      string `json:"domain"`
	Issuer      string `json:"issuer"`
	Source      string `json:"source"`
}

// ebiaInfo carries the magic link for the EBIA fallback. In a real deployment
// this link would be emailed to the user; for the demo it is shown in the UI.
type ebiaInfo struct {
	MagicLink string `json:"magicLink"`
}

// passwordRequest is the payload posted when a local user submits their
// password in the second step.
type passwordRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// errorResponse is a small uniform error envelope.
type errorResponse struct {
	Error string `json:"error"`
}

func main() {
	r := gin.Default()
	r.Use(corsMiddleware())

	// Liveness/readiness probe used by docker-compose and manual checks.
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	api.POST("/login/start", handleLoginStart)
	api.POST("/login/password", handleLoginPassword)
	api.GET("/login/result", handleLoginResult)
	api.GET("/oauth/google/start", handleGoogleStart)

	// Identity-wallet login: the frontend requests a challenge, the browser
	// extension signs it with the key committed in its PK Token, and the
	// frontend posts the PK Token + signed challenge back for verification.
	api.GET("/wallet/challenge", handleWalletChallenge)
	api.POST("/wallet/verify", handleWalletVerify)
	api.GET("/ebia/info", handleEBIAInfo)

	// Blind-relay login (split-PKCE). /relay/start redirects the browser
	// to the OP via the relay's registered redirect URI; the relay forwards the
	// code to /relay/callback, where the Verifier redeems it itself. See
	// relayflow.go.
	api.GET("/relay/start", handleRelayStart)
	api.GET("/relay/callback", handleRelayCallback)

	// Google redirects the browser here after consent. This path must match the
	// redirect URI registered for the OAuth client, so it lives at the root
	// (not under /api). See oauth.go.
	r.GET(googleCallbackPath, handleGoogleCallback)

	// EBIA magic-link destination, visited directly by the user's browser.
	r.GET("/ebia/verify", handleEBIAVerify)

	// The Verifier's public JWKS for routing-state signatures (JAR). The blind
	// relay fetches this from the verifier origin to verify the signed OAuth
	// state before relaying. At the root (domain control), not under /api.
	r.GET("/.well-known/byoid-verifier", handleVerifierJWKS)

	port := os.Getenv("PORT")
	if port == "" {
		// 11110 is one of the loopback ports registered for the OpenPubkey
		// Google client (see oauth.go); 3000 collides with common dev servers.
		port = "11110"
	}
	// gin.Default already logs; Run blocks until the process is stopped.
	_ = r.Run(":" + port)
}

// normalizeEmail lower-cases and trims the email and reports whether it looks
// like a valid address.
func normalizeEmail(raw string) (string, bool) {
	email := strings.ToLower(strings.TrimSpace(raw))
	return email, emailRe.MatchString(email)
}

// handleLoginStart validates the submitted email and decides how the user
// should authenticate.
func handleLoginStart(c *gin.Context) {
	var req loginStartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	email, ok := normalizeEmail(req.Email)
	if !ok {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "please enter a valid email address"})
		return
	}

	// Safe: the regex guarantees exactly one "@" with content on both sides.
	domain := email[strings.LastIndex(email, "@")+1:]

	resp := loginStartResponse{Email: email, Domain: domain}
	switch {
	case hasLocalAccount(email):
		// The Verifier can authenticate this user on its own.
		resp.Method = "password"

	case isGoogleBoundDomain(domain):
		// The Verifier already has a client binding with this user's provider,
		// so the domain->issuer relationship is trusted by that binding.
		resp.Method = "oauth"
		resp.Provider = "google"
		resp.Trust = &trustInfo{
			Established: true,
			Domain:      domain,
			Issuer:      googleIssuer,
			Source:      "known-provider",
		}

	default:
		// No pre-binding with a known provider. First ask the namespace domain
		// for its BYOID configuration (/.well-known/byoid-configuration). If it
		// delegates a blind relay and the declared issuer is not one the Verifier
		// already has a binding with, route the login through the relay.
		// This is checked before WebFinger issuer discovery.
		if cfg, ok := discoverByoidConfig(c.Request.Context(), domain); ok &&
			cfg.hasRelayDelegation() && !isPreBoundIssuer(cfg.Issuer) {
			ns := cfg.Namespace
			if ns == "" {
				ns = domain
			}
			resp.Method = "relay"
			resp.Relay = &relayInfo{
				Namespace:        ns,
				Issuer:           cfg.Issuer,
				RelayRedirectURI: cfg.RelayRedirectURI,
				WellKnown:        cfg.Raw,
			}
			break
		}

		// No relay delegation: ask the namespace domain (over HTTPS) which issuer
		// it authorizes for its users via WebFinger. If it declares one, we can
		// trust that domain->issuer relationship without any change to, or claim
		// from, the issuer (OP).
		if issuer, ok := discoverIssuer(c.Request.Context(), email, domain); ok {
			resp.Method = "trust"
			resp.Trust = &trustInfo{
				Established: true,
				Domain:      domain,
				Issuer:      issuer,
				Source:      "webfinger",
			}
			break
		}

		// Trust could not be established. Fall back to proving mailbox control
		// via EBIA (a magic link). No dead ends: every email has this path.
		link, err := newEBIAChallenge(email)
		if err != nil {
			c.JSON(http.StatusInternalServerError, errorResponse{Error: "could not start verification"})
			return
		}
		resp.Method = "ebia"
		resp.EBIA = &ebiaInfo{MagicLink: link}
	}

	c.JSON(http.StatusOK, resp)
}

// hasLocalAccount reports whether the (normalized) email has a local
// username/password account with the Verifier.
func hasLocalAccount(email string) bool {
	_, ok := localPassword(email)
	return ok
}

// handleLoginPassword verifies a local account's password. This path is only
// valid for users returned as method "password" by /api/login/start.
func handleLoginPassword(c *gin.Context) {
	var req passwordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	email, ok := normalizeEmail(req.Email)
	if !ok {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "please enter a valid email address"})
		return
	}

	want, exists := localPassword(email)
	// Compare in constant time and always compare, even when the account does
	// not exist, so we do not leak account existence via timing. The generic
	// error message avoids leaking it via the response.
	match := subtle.ConstantTimeCompare([]byte(req.Password), []byte(want)) == 1
	if !exists || !match {
		c.JSON(http.StatusUnauthorized, errorResponse{Error: "incorrect email or password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok", "email": email})
}

// corsMiddleware allows the frontend to call the API directly during local
// development (e.g. the Vite dev server on a different origin). In the
// docker-compose setup nginx proxies /api to this service so requests are
// same-origin, but permissive CORS here keeps native `go run` + `npm run dev`
// working without extra config.
func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
