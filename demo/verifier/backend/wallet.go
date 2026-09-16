package main

// Identity-wallet login: verify a PK Token presented by the browser extension,
// with a proof-of-possession over a fresh challenge.
//
// This is the payoff of the whole design. With no pre-binding, the Verifier
// establishes a trusted domain->issuer relationship (via WebFinger, or a known
// provider binding), then the user's wallet proves, in one round-trip:
//
//   1. VerifyPKToken:      the PK Token carries a real OP signature (checked
//      against the issuer's JWKS) and commits the user's ephemeral public key
//      in the OIDC nonce. The OP is unmodified and unaware.
//   2. VerifySignedMessage: the wallet signed a fresh, server-issued challenge
//      with the private key committed inside that PK Token -- proof the live
//      caller holds the key the OP certified (not a replayed bearer token).
//
// The Verifier additionally requires that the token's email equals the email
// the challenge was issued for, and that the token's issuer equals the issuer
// trusted for that email's domain. Together this proves: "the caller controls
// an account at <domain>'s authorized issuer for <email>."
//
// Challenge state is kept in memory; no database.

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openpubkey/openpubkey/pktoken"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/verifier"
)

// Microsoft (Azure) client reused from OpenPubkey's providers/azure.go. The
// default tenant is Microsoft's "consumers" tenant, giving a fixed issuer we
// can verify against.
const (
	msTenant   = "9188040d-6c67-4c5b-b112-36a304b66dad"
	msClientID = "096ce0a3-5e72-4da8-9c86-12924b294a01"
	msIssuer   = "https://login.microsoftonline.com/" + msTenant + "/v2.0"
)

// walletChallengeTTL bounds how long a challenge is valid.
// 10 minutes leaves room for a mid-login token refresh (a full re-auth) before
// the user completes proof-of-possession.
const walletChallengeTTL = 10 * time.Minute

// anyIssuer is a sentinel meaning "accept any issuer the wallet verifier
// already trusts", used when authority comes from mailbox control (EBIA) rather
// than a domain->issuer declaration.
const anyIssuer = "*"

// walletChallenge ties a challenge nonce to the email it was issued for.
type walletChallenge struct {
	email   string
	created time.Time
}

var (
	wcMu             sync.Mutex
	walletChallenges = map[string]*walletChallenge{}

	pktVerifierOnce sync.Once
	pktVerifier     *verifier.Verifier
	pktVerifierErr  error
)

// walletVerifier builds (once) an OpenPubkey verifier that accepts PK Tokens
// from the OPs our wallet supports (Google and Microsoft), checking the OP
// signature, the nonce commitment, and the audience (client id).
func walletVerifier() (*verifier.Verifier, error) {
	pktVerifierOnce.Do(func() {
		google := providers.NewProviderVerifier(googleIssuer, providers.ProviderVerifierOpts{
			ClientID:   googleClientID,
			CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		})
		microsoft := providers.NewProviderVerifier(msIssuer, providers.ProviderVerifierOpts{
			ClientID:   msClientID,
			CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		})
		pktVerifier, pktVerifierErr = verifier.NewFromMany(
			[]verifier.ProviderVerifier{google, microsoft},
		)
	})
	return pktVerifier, pktVerifierErr
}

// trustedIssuerForDomain returns the issuer the Verifier trusts for a domain,
// and how that trust was established, or ok=false if none. This mirrors the
// decision in handleLoginStart so the wallet check enforces the same
// domain->issuer relationship.
func trustedIssuerForDomain(ctx context.Context, email, domain string) (issuer, source string, ok bool) {
	if isGoogleBoundDomain(domain) {
		return googleIssuer, "known-provider", true
	}
	if iss, found := discoverIssuer(ctx, email, domain); found {
		return iss, "webfinger", true
	}
	return "", "", false
}

// walletChallengeResponse is returned to the frontend to hand to the wallet.
type walletChallengeResponse struct {
	Email     string `json:"email"`
	Challenge string `json:"challenge"`
}

// handleWalletChallenge mints a fresh challenge for an email. The wallet must
// sign exactly this value; the signature is checked in handleWalletVerify.
func handleWalletChallenge(c *gin.Context) {
	email, ok := normalizeEmail(c.Query("email"))
	if !ok {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "please provide a valid email"})
		return
	}
	nonce, err := randomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse{Error: "could not create challenge"})
		return
	}
	wcMu.Lock()
	gcWalletChallenges()
	walletChallenges[nonce] = &walletChallenge{email: email, created: time.Now()}
	wcMu.Unlock()

	walletLogf("challenge issued  email=%s  challenge=%s  (valid %s)", email, nonce, walletChallengeTTL)
	c.JSON(http.StatusOK, walletChallengeResponse{Email: email, Challenge: nonce})
}

// walletLogf prints a step in the identity-wallet proof-of-possession flow with
// a consistent, greppable prefix so the whole exchange is easy to follow.
func walletLogf(format string, args ...any) {
	log.Printf("[BYOID:verifier] "+format, args...)
}

// abbrevBE shortens a long value (e.g. a PK Token) to a prefix + length for
// logging, so the console stays readable.
func abbrevBE(s string) string {
	if len(s) <= 28 {
		return s
	}
	return s[:14] + "…(" + itoa(len(s)) + " chars)"
}

func itoa(n int) string { return strconv.Itoa(n) }

// gcWalletChallenges drops expired challenges. Caller must hold wcMu.
func gcWalletChallenges() {
	now := time.Now()
	for k, v := range walletChallenges {
		if now.Sub(v.created) > walletChallengeTTL {
			delete(walletChallenges, k)
		}
	}
}

// walletVerifyRequest is what the frontend posts after the wallet responds.
type walletVerifyRequest struct {
	Email     string `json:"email"`
	Challenge string `json:"challenge"`
	// PKT is the PK Token as JSON (JWS JSON serialization), as produced by the
	// extension's WASM module.
	PKT string `json:"pkt"`
	// OSM is the OpenPubkey Signed Message: the challenge signed by the key
	// committed in the PK Token (compact JWS).
	OSM string `json:"osm"`
	// EBIASession, when set, is a session id proving the user already
	// demonstrated mailbox control for this email (they clicked the magic
	// link). In that case authority comes from mailbox control, so the
	// domain->issuer trust requirement is skipped -- we only require a valid PK
	// Token, proof-of-possession, and that the token's email matches.
	EBIASession string `json:"ebiaSession"`
}

// idTokenClaims are the ID token claims we read for the membership decision.
type idTokenClaims struct {
	Issuer        string `json:"iss"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	HostedDomain  string `json:"hd"`
	Subject       string `json:"sub"`
}

// handleWalletVerify verifies the presented PK Token and proof-of-possession.
func handleWalletVerify(c *gin.Context) {
	var req walletVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "invalid request body"})
		return
	}

	email, ok := normalizeEmail(req.Email)
	if !ok {
		c.JSON(http.StatusBadRequest, errorResponse{Error: "please provide a valid email"})
		return
	}

	walletLogf("verify request received  email=%s  challenge=%s  pkt=%s  osm=%s",
		email, req.Challenge, abbrevBE(req.PKT), abbrevBE(req.OSM))

	// 1. Consume the challenge (single-use) and check it was issued for this
	//    email and is still fresh.
	wcMu.Lock()
	ch := walletChallenges[req.Challenge]
	delete(walletChallenges, req.Challenge)
	wcMu.Unlock()
	if ch == nil || time.Since(ch.created) > walletChallengeTTL {
		walletLogf("  step 1/5 challenge check FAILED: expired or unknown")
		c.JSON(http.StatusBadRequest, errorResponse{Error: "challenge expired or unknown"})
		return
	}
	if ch.email != email {
		walletLogf("  step 1/5 challenge check FAILED: issued for %s, not %s", ch.email, email)
		c.JSON(http.StatusBadRequest, errorResponse{Error: "challenge was issued for a different email"})
		return
	}
	walletLogf("  step 1/5 challenge OK: fresh and issued for this email")

	// 2. Determine the trust basis. If an EBIA session is presented, the user
	//    already proved mailbox control for this email by clicking the magic
	//    link, so mailbox control -- not a domain->issuer declaration -- carries
	//    the authority. Otherwise the token's issuer must be the one trusted for
	//    the email's domain (WebFinger or a known provider binding).
	trust := trustedIssuerForDomain
	if req.EBIASession != "" {
		if !consumeEBIASession(req.EBIASession, email) {
			walletLogf("  step 2/5 trust basis FAILED: EBIA session invalid/expired")
			c.JSON(http.StatusUnauthorized, errorResponse{Error: "email verification expired; please verify your email again"})
			return
		}
		// Accept any issuer the wallet verifier already trusts (Google/Microsoft),
		// since VerifyPKToken still requires a real, known OP.
		trust = func(ctx context.Context, email, domain string) (string, string, bool) {
			return anyIssuer, "ebia", true
		}
		walletLogf("  step 2/5 trust basis: EBIA (mailbox control proven) — any known issuer accepted")
	} else {
		walletLogf("  step 2/5 trust basis: domain→issuer (WebFinger or known provider binding)")
	}

	// 3. Build the OpenPubkey verifier and verify the presentation.
	v, err := walletVerifier()
	if err != nil {
		c.JSON(http.StatusInternalServerError, errorResponse{Error: "verifier unavailable"})
		return
	}
	res, verr := verifyWalletPresentation(
		c.Request.Context(), v, trust,
		walletPresentation{Email: email, Challenge: req.Challenge, PKT: req.PKT, OSM: req.OSM},
	)
	if verr != nil {
		c.JSON(verr.status, errorResponse{Error: verr.msg})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
		"email":  res.Email,
		"issuer": res.Issuer,
		"source": res.Source,
		"sub":    res.Subject,
	})
}

// trustFn resolves the issuer trusted for an email's domain, and how that trust
// was established. It mirrors handleLoginStart's decision.
type trustFn func(ctx context.Context, email, domain string) (issuer, source string, ok bool)

// walletPresentation is the verified input to verifyWalletPresentation.
type walletPresentation struct {
	Email     string
	Challenge string
	PKT       string
	OSM       string
}

// walletVerifyResult is the outcome of a successful verification.
type walletVerifyResult struct {
	Email   string
	Issuer  string
	Source  string
	Subject string
}

// walletVerifyError carries an HTTP status alongside the message.
type walletVerifyError struct {
	status int
	msg    string
}

func (e *walletVerifyError) Error() string { return e.msg }

func vErr(status int, msg string) *walletVerifyError { return &walletVerifyError{status, msg} }

// verifyWalletPresentation performs the cryptographic and policy checks that
// prove the caller controls, for the given email, an account at the issuer the
// Verifier trusts for that email's domain:
//
//  1. VerifyPKToken:      OP signature (via JWKS), nonce commitment, audience.
//  2. VerifySignedMessage: the challenge was signed by the key committed in
//     the PK Token (proof-of-possession).
//  3. email claim == the authenticated email.
//  4. issuer claim == the issuer trusted for the email's domain.
//
// It is separated from the HTTP handler so it can be tested with a mock OP.
func verifyWalletPresentation(ctx context.Context, v *verifier.Verifier, trusted trustFn, p walletPresentation) (*walletVerifyResult, *walletVerifyError) {
	var pkt pktoken.PKToken
	if err := json.Unmarshal([]byte(p.PKT), &pkt); err != nil {
		return nil, vErr(http.StatusBadRequest, "could not parse PK Token")
	}

	if err := v.VerifyPKToken(ctx, &pkt); err != nil {
		walletLogf("  step 3/5 VerifyPKToken FAILED: %v", err)
		return nil, vErr(http.StatusUnauthorized, "PK Token verification failed: "+err.Error())
	}
	walletLogf("  step 3/5 VerifyPKToken OK: OP signature valid (JWKS), ephemeral key committed in nonce")

	content, err := pkt.VerifySignedMessage([]byte(p.OSM))
	if err != nil {
		walletLogf("  step 4/5 proof-of-possession FAILED: %v", err)
		return nil, vErr(http.StatusUnauthorized, "proof-of-possession failed: "+err.Error())
	}
	if !subtleConstantEquals(string(content), p.Challenge) {
		walletLogf("  step 4/5 proof-of-possession FAILED: signed message != challenge")
		return nil, vErr(http.StatusUnauthorized, "signed message does not match the challenge")
	}
	walletLogf("  step 4/5 proof-of-possession OK: challenge signed by the committed key")

	var claims idTokenClaims
	if err := json.Unmarshal(pkt.Payload, &claims); err != nil {
		return nil, vErr(http.StatusInternalServerError, "could not read token claims")
	}

	if !strings.EqualFold(strings.TrimSpace(claims.Email), p.Email) {
		walletLogf("  step 5/5 policy FAILED: token email %q != authenticated %q", claims.Email, p.Email)
		return nil, vErr(http.StatusUnauthorized, "PK Token is for a different email")
	}

	domain := p.Email[strings.LastIndex(p.Email, "@")+1:]
	trustedIssuer, source, isTrusted := trusted(ctx, p.Email, domain)
	if !isTrusted {
		walletLogf("  step 5/5 policy FAILED: no trusted issuer for domain %q", domain)
		return nil, vErr(http.StatusUnauthorized, "no trusted issuer for this domain")
	}
	// anyIssuer means the caller established authority another way (mailbox
	// control via EBIA), so we accept any issuer the wallet verifier already
	// trusts. VerifyPKToken above still required a real, known OP.
	if trustedIssuer != anyIssuer &&
		strings.TrimRight(claims.Issuer, "/") != strings.TrimRight(trustedIssuer, "/") {
		walletLogf("  step 5/5 policy FAILED: token issuer %q != trusted %q", claims.Issuer, trustedIssuer)
		return nil, vErr(http.StatusUnauthorized, "PK Token issuer is not the issuer trusted for this domain")
	}
	walletLogf("  step 5/5 policy OK: email matches; issuer trusted (%s via %s)", claims.Issuer, source)
	walletLogf("VERIFIED ✓  %s controls a key the OP bound to this identity  (source=%s)", claims.Email, source)

	return &walletVerifyResult{
		Email:   claims.Email,
		Issuer:  claims.Issuer,
		Source:  source,
		Subject: claims.Subject,
	}, nil
}

// subtleConstantEquals compares two strings in constant time.
func subtleConstantEquals(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var v byte
	for i := 0; i < len(a); i++ {
		v |= a[i] ^ b[i]
	}
	return v == 0
}
