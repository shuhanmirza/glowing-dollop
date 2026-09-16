package main

// JAR-style signed routing state for the blind-relay flow.
//
// The blind relay needs to trust the routing instruction it acts on — chiefly
// the callback it relays the code to. We authenticate that instruction the same
// way trust is rooted everywhere in this project: by domain control. The
// Verifier signs the OAuth `state` as a compact ES256 JWS and publishes its
// public key at <verifier-origin>/.well-known/byoid-verifier. The relay fetches
// that JWKS and verifies the signature before relaying, so it will only relay to
// a callback whose domain proved it issued the request. (Adapted from RFC 9101
// JAR: here the relay — not the OP — verifies the signed request.)
//
// The signed state is not secret (the relay must read it to route); the point
// is integrity + origin authentication, not confidentiality.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-jose/go-jose/v4"
)

// routingStateTyp is the explicit JWT type header (RFC 8725), so the relay can
// reject tokens not minted for this purpose.
const routingStateTyp = "byoid-routing+jwt"

// routingClaims is the payload of the signed routing state.
type routingClaims struct {
	Aud string `json:"aud"` // relay origin (bind to this relay)
	CB  string `json:"cb"`  // verifier callback; ALSO the JWKS
	//                                       discovery root — the relay fetches the
	//                                       key from the callback origin, so no
	//                                       separate `iss` claim is carried.
	SID   string `json:"sid"`            // verifier flow lookup key
	Step  bool   `json:"step,omitempty"` // step-by-step demo
	OP    string `json:"op"`             // OP issuer, for the consent page
	Scope string `json:"scope"`          // scopes the verifier will obtain
	JTI   string `json:"jti"`            // single-use id (relay replay guard)
	IAT   int64  `json:"iat"`            // issued-at (unix seconds)
	EXP   int64  `json:"exp"`            // expiry (unix seconds)
}

var (
	jarOnce sync.Once
	jarKey  *ecdsa.PrivateKey
	jarKID  string
)

// jarSigningKey lazily generates the Verifier's ES256 signing key. A fresh key
// per process is fine for the demo; the public half is published via JWKS.
func jarSigningKey() (*ecdsa.PrivateKey, string) {
	jarOnce.Do(func() {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic("byoid: cannot generate JAR signing key: " + err.Error())
		}
		jarKey = k
		// Stable kid = base64url(SHA-256(uncompressed public point))[:16].
		pub := elliptic.Marshal(k.Curve, k.X, k.Y) //nolint:staticcheck // fine for a kid
		sum := sha256.Sum256(pub)
		jarKID = base64.RawURLEncoding.EncodeToString(sum[:])[:16]
	})
	return jarKey, jarKID
}

// signRoutingState signs the claims as a compact ES256 JWS.
func signRoutingState(claims routingClaims) (string, error) {
	key, kid := jarSigningKey()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	opts := (&jose.SignerOptions{}).
		WithType(jose.ContentType(routingStateTyp)).
		WithHeader("kid", kid)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

// verifyOwnRoutingState verifies a state token with our own public key and
// returns its claims. Used at the callback to read sid/step from a token we
// signed (defence in depth — the sid lookup is the real authority).
func verifyOwnRoutingState(compact string) (*routingClaims, error) {
	key, _ := jarSigningKey()
	sig, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, err
	}
	payload, err := sig.Verify(key.Public())
	if err != nil {
		return nil, err
	}
	var claims routingClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	return &claims, nil
}

// handleVerifierJWKS serves the Verifier's public signing key so the relay can
// verify routing states. Served at the verifier origin (domain control).
func handleVerifierJWKS(c *gin.Context) {
	key, kid := jarSigningKey()
	jwk := jose.JSONWebKey{
		Key:       key.Public(),
		KeyID:     kid,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}
	c.Header("Cache-Control", "public, max-age=300")
	c.JSON(http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}})
}

// verifierOrigin is the Verifier's public origin used as the JWS issuer and the
// base for the callback. The relay fetches the JWKS from here, so it must be a
// hostname the relay can resolve (a compose alias in the demo).
func verifierOrigin() string {
	if v := os.Getenv("VERIFIER_ORIGIN"); v != "" {
		return v
	}
	return "http://xyz.localhost:11110"
}

// relayOrigin is the blind relay's origin, used as the JWS audience so a state
// minted for this relay cannot be replayed at another.
func relayOrigin() string {
	if v := os.Getenv("RELAY_ORIGIN"); v != "" {
		return v
	}
	return "http://relayoidc.localhost:9090"
}

// routingStateTTL bounds how long a signed state is valid. It must cover the
// user's OP login plus the consent click, so it matches the overall flow TTL.
const routingStateTTL = stateTTL

// newJTI returns a random single-use id for a routing state.
func newJTI() (string, error) { return randomToken(16) }

// nowUnix is a small indirection for timestamps (kept simple/testable).
func nowUnix() int64 { return time.Now().Unix() }
