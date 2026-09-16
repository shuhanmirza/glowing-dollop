package main

// Verification of the Verifier's signed routing state (JAR-style).
//
// The relay will only relay an authorization code to a callback if the routing
// instruction is authentic. The Verifier signs the OAuth `state` as a compact
// ES256 JWS. Trust is rooted in domain control:
//
//   - The relay locates the public key from the CALLBACK origin, not from a
//     claim: it fetches <callback-origin>/.well-known/byoid-verifier. So the
//     domain that will receive the code is, by construction, the same domain
//     whose key must have signed the request — a forged `iss`-style claim
//     cannot point the key lookup somewhere else.
//   - A valid signature under that JWKS proves the request came from the
//     callback's own domain.
//
// Order of checks is deliberate: cheap, security-relevant claims (typ, aud,
// exp) are checked on the UNVERIFIED payload FIRST, so a junk or misaddressed
// request is dropped before any outbound JWKS fetch or signature crypto. The
// JWKS fetch is SSRF-guarded (hostnames only, public IPs, no redirects, pinned
// dial) with an explicit allowlist carve-out for the demo's *.localhost origins.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// routingClaims mirrors the Verifier's signed routing state (see backend
// jar.go). The `iss` claim the Verifier sets is intentionally ignored by the
// relay: the key is located from the callback origin, so nothing about the key
// lookup depends on a claim the relay has not yet verified.
type routingClaims struct {
	Aud   string `json:"aud"`
	CB    string `json:"cb"`
	SID   string `json:"sid"`
	Step  bool   `json:"step,omitempty"`
	OP    string `json:"op"`
	Scope string `json:"scope"`
	JTI   string `json:"jti"`
	IAT   int64  `json:"iat"`
	EXP   int64  `json:"exp"`
}

const routingStateTyp = "byoid-routing+jwt"

// precheckState parses the state WITHOUT verifying the signature and validates
// the cheap, security-relevant claims (typ, aud, exp, iat, a usable callback)
// so a junk or misaddressed request is rejected BEFORE any outbound JWKS fetch
// or signature verification. The returned claims are UNVERIFIED — used only to
// reject early and to locate the JWKS from the callback origin. Nothing here is
// trusted; the signature is checked in verifyRoutingState.
func precheckState(compact string) (*jose.JSONWebSignature, *routingClaims, error) {
	sig, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256})
	if err != nil {
		return nil, nil, fmt.Errorf("parse: %w", err)
	}
	if len(sig.Signatures) == 0 {
		return nil, nil, fmt.Errorf("no signatures")
	}
	// Reject tokens not minted for this purpose (RFC 8725 explicit typing).
	if typ, _ := sig.Signatures[0].Header.ExtraHeaders[jose.HeaderType].(string); typ != routingStateTyp {
		return nil, nil, fmt.Errorf("unexpected typ %q", typ)
	}

	var c routingClaims
	if err := json.Unmarshal(sig.UnsafePayloadWithoutVerification(), &c); err != nil {
		return nil, nil, fmt.Errorf("payload: %w", err)
	}
	if err := checkAudExp(&c); err != nil {
		return nil, nil, err
	}
	// The callback must be a usable http(s) URL — we derive the JWKS location
	// from its origin.
	if u, err := url.Parse(c.CB); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, nil, fmt.Errorf("callback is not a valid http(s) url")
	}
	return sig, &c, nil
}

// checkAudExp validates the audience and freshness of (verified or unverified)
// claims. Kept separate so it can run both pre-fetch and post-verify.
func checkAudExp(c *routingClaims) error {
	if c.Aud != relayOrigin() {
		return fmt.Errorf("aud %q is not this relay", c.Aud)
	}
	now := time.Now().Unix()
	if c.EXP == 0 || now > c.EXP {
		return fmt.Errorf("expired")
	}
	if c.IAT != 0 && c.IAT > now+60 {
		return fmt.Errorf("issued in the future")
	}
	return nil
}

// verifyRoutingState authenticates a signed routing state and returns its
// claims. It pre-checks aud/exp before any fetch, locates the JWKS from the
// callback origin, verifies the signature, then re-checks aud/exp on the
// verified payload. It does NOT consume the jti unless consume=true (so a GET
// of the consent page stays idempotent; the relay step consumes it).
func verifyRoutingState(compact string, consume bool) (*routingClaims, error) {
	sig, unsafe, err := precheckState(compact)
	if err != nil {
		return nil, err
	}

	// Locate the key from the callback origin — never from an unverified claim.
	base := originOf(unsafe.CB)
	kid := sig.Signatures[0].Header.KeyID
	key, err := verifierKey(base, kid)
	if err != nil {
		return nil, err
	}

	payload, err := sig.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("bad signature: %w", err)
	}
	var claims routingClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	// Re-check on the verified payload (defence in depth: the signed claims are
	// what we act on, not the unverified copy used for pre-check/lookup).
	if err := checkAudExp(&claims); err != nil {
		return nil, err
	}
	if originOf(claims.CB) != base {
		return nil, fmt.Errorf("verified callback origin changed")
	}
	if consume {
		if err := consumeJTI(claims.JTI, claims.EXP); err != nil {
			return nil, err
		}
	}
	return &claims, nil
}

// verificationInfo describes how a routing state was authenticated, for display
// on the consent page so the user can see the trust chain: the signature was
// checked against the public key published at the callback domain's well-known
// JWKS.
type verificationInfo struct {
	SignerHost string // callback host whose key signed the state
	JWKSURL    string // where the relay fetched the public key
	KID        string // key id used
	Alg        string // signature algorithm (ES256)
}

// routingVerification derives the display metadata for a state the relay has
// already verified. base is the callback origin the key was fetched from.
func routingVerification(base, compact string) verificationInfo {
	info := verificationInfo{
		SignerHost: hostOnly(base),
		JWKSURL:    strings.TrimRight(base, "/") + "/.well-known/byoid-verifier",
	}
	if sig, err := jose.ParseSigned(compact, []jose.SignatureAlgorithm{jose.ES256}); err == nil && len(sig.Signatures) > 0 {
		info.KID = sig.Signatures[0].Header.KeyID
		info.Alg = string(sig.Signatures[0].Header.Algorithm)
	}
	return info
}

// relayOrigin is this relay's own origin (the expected JWS audience).
func relayOrigin() string {
	if v := os.Getenv("RELAY_ORIGIN"); v != "" {
		return v
	}
	return "http://relayoidc.localhost:9090"
}

// ---- JWKS fetch (SSRF-guarded) + bounded cache ----

type cachedKeys struct {
	set     jose.JSONWebKeySet
	expires time.Time
}

const jwksCacheMax = 128

var (
	jwksMu    sync.Mutex
	jwksCache = map[string]cachedKeys{}
)

// verifierKey fetches (and caches) the JWKS at <base>/.well-known/byoid-verifier
// and returns the key with the given kid.
func verifierKey(base, kid string) (interface{}, error) {
	jwksMu.Lock()
	c, ok := jwksCache[base]
	jwksMu.Unlock()
	if !ok || time.Now().After(c.expires) {
		set, err := fetchJWKS(base)
		if err != nil {
			return nil, err
		}
		c = cachedKeys{set: set, expires: time.Now().Add(5 * time.Minute)}
		jwksMu.Lock()
		evictIfFull()
		jwksCache[base] = c
		jwksMu.Unlock()
	}
	keys := c.set.Key(kid)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no key %q at %s", kid, base)
	}
	return keys[0].Key, nil
}

// evictIfFull bounds the cache so an attacker naming many distinct (public,
// JWKS-serving) origins cannot grow it without limit. Caller holds jwksMu.
func evictIfFull() {
	if len(jwksCache) < jwksCacheMax {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(jwksCache))
	for k, v := range jwksCache {
		all = append(all, kv{k, v.expires})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	// Drop the soonest-expiring 10% (at least one).
	drop := len(all)/10 + 1
	for i := 0; i < drop && i < len(all); i++ {
		delete(jwksCache, all[i].k)
	}
}

// fetchJWKS retrieves the verifier's JWKS from base, guarding against SSRF.
func fetchJWKS(base string) (jose.JSONWebKeySet, error) {
	var empty jose.JSONWebKeySet
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return empty, fmt.Errorf("bad base url")
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	client := &http.Client{
		Timeout: 4 * time.Second,
		// Never follow redirects: a redirect target would bypass the SSRF
		// checks below (e.g. redirect to 169.254.169.254 or an internal host).
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects are not allowed for JWKS discovery")
		},
	}

	if !allowedJWKSHosts()[host] {
		// Non-carve-out host: reject IP literals, resolve ONCE, require a public
		// address, and pin the dial to that IP so a rebind between check and
		// connect cannot redirect us to an internal address.
		ip, err := publicDialIP(host)
		if err != nil {
			return empty, err
		}
		dial := net.JoinHostPort(ip.String(), port)
		client.Transport = &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, dial)
			},
		}
	}
	// Carve-out hosts (e.g. xyz.localhost) are dialled normally: the operator
	// explicitly trusts them, and they intentionally resolve to loopback/private
	// addresses in the demo.

	endpoint := strings.TrimRight(base, "/") + "/.well-known/byoid-verifier"
	resp, err := client.Get(endpoint)
	if err != nil {
		return empty, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return empty, fmt.Errorf("jwks http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return empty, err
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(body, &set); err != nil {
		return empty, err
	}
	if len(set.Keys) == 0 {
		return empty, fmt.Errorf("empty jwks")
	}
	return set, nil
}

// allowedJWKSHosts is the demo carve-out: these hostnames are reachable for
// JWKS discovery even though they resolve to loopback/private addresses.
func allowedJWKSHosts() map[string]bool {
	raw := os.Getenv("VERIFIER_ALLOWED_HOSTS")
	if raw == "" {
		raw = "xyz.localhost,localhost,127.0.0.1"
	}
	m := map[string]bool{}
	for _, h := range strings.Split(raw, ",") {
		if h = strings.TrimSpace(h); h != "" {
			m[h] = true
		}
	}
	return m
}

// publicDialIP resolves a (non-carve-out) host and returns a public IP to dial.
// It rejects IP-literal hosts and any host that resolves only to
// private/loopback/link-local addresses, so a JWKS fetch cannot be aimed at
// internal infrastructure.
func publicDialIP(host string) (net.IP, error) {
	if net.ParseIP(host) != nil {
		return nil, fmt.Errorf("ip-literal issuer host %q not allowed", host)
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %q: %w", host, err)
	}
	for _, ip := range ips {
		if isPublicIP(ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("host %q resolves only to disallowed addresses", host)
}

// isPublicIP reports whether ip is a routable public address (not loopback,
// private/ULA, link-local, or unspecified).
func isPublicIP(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified())
}

// guardSSRF reports whether a JWKS fetch to host is permitted. Carve-out hosts
// pass; everything else must be a resolvable public hostname (no IP literals,
// no private/loopback targets). Used as an early guard and in tests.
func guardSSRF(host string) error {
	if allowedJWKSHosts()[host] {
		return nil
	}
	_, err := publicDialIP(host)
	return err
}

// ---- jti single-use cache ----

var (
	jtiMu   sync.Mutex
	jtiSeen = map[string]int64{} // jti -> expiry unix
)

// consumeJTI records a jti as used and rejects reuse. Expired entries are swept.
func consumeJTI(jti string, exp int64) error {
	if jti == "" {
		return fmt.Errorf("missing jti")
	}
	now := time.Now().Unix()
	jtiMu.Lock()
	defer jtiMu.Unlock()
	for k, e := range jtiSeen {
		if now > e {
			delete(jtiSeen, k)
		}
	}
	if _, used := jtiSeen[jti]; used {
		return fmt.Errorf("state already used (replay)")
	}
	jtiSeen[jti] = exp
	return nil
}
