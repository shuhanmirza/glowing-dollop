package main

// Domain -> issuer discovery via WebFinger.
//
// This is the "no pre-binding" case: the Verifier has never met the user's
// domain and shares no federation with it. To decide whether it can trust a
// domain->issuer relationship, the Verifier asks the *namespace domain* (the
// email's domain) directly, using WebFinger + OpenID Connect Issuer Discovery
// (RFC 7033 / OpenID Connect Discovery 1.0 section 2):
//
//	GET https://<domain>/.well-known/webfinger
//	    ?resource=acct:<email>&rel=http://openid.net/specs/connect/1.0/issuer
//
// The authority here comes from *where* this is fetched: directly from the
// namespace domain over TLS. Being able to serve this response under the
// domain's certificate is itself proof of control over the domain, so the
// issuer it names is one the domain owner has authorized. We deliberately do
// NOT rely on the issuer (the OpenID Provider) declaring anything about the
// domain -- the OP stays unmodified and unaware.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// oidcIssuerRel is the WebFinger link relation for OpenID issuer discovery.
const oidcIssuerRel = "http://openid.net/specs/connect/1.0/issuer"

// webFingerTimeout bounds the discovery fetch so login start stays responsive
// for domains that do not serve WebFinger.
const webFingerTimeout = 4 * time.Second

// maxWebFingerBody caps how much we read from an untrusted domain's response.
const maxWebFingerBody = 64 * 1024

// jrd is the subset of the JSON Resource Descriptor (RFC 7033) we need.
type jrd struct {
	Subject string `json:"subject"`
	Links   []struct {
		Rel  string `json:"rel"`
		Href string `json:"href"`
	} `json:"links"`
}

// discoverIssuer asks the namespace domain which OpenID issuer it authorizes
// for the given user. It returns the issuer URL and true if the domain
// declares one over HTTPS.
func discoverIssuer(ctx context.Context, email, domain string) (string, bool) {
	endpoint := url.URL{
		Scheme: "https",
		Host:   domain,
		Path:   "/.well-known/webfinger",
	}
	q := url.Values{}
	q.Set("resource", "acct:"+email)
	q.Set("rel", oidcIssuerRel)
	endpoint.RawQuery = q.Encode()

	// A dedicated client that only follows redirects that stay on the same
	// host over HTTPS: the declaration must come from the namespace domain
	// itself, not from wherever it might redirect us.
	client := &http.Client{
		Timeout: webFingerTimeout,
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			if r.URL.Scheme != "https" || r.URL.Host != domain {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
	return fetchIssuer(ctx, client, endpoint.String())
}

// fetchIssuer performs the WebFinger GET and extracts the issuer link. It is
// separated from discoverIssuer so it can be tested against a local server.
func fetchIssuer(ctx context.Context, client *http.Client, endpoint string) (string, bool) {
	ctx, cancel := context.WithTimeout(ctx, webFingerTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("Accept", "application/jrd+json, application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", false
	}

	var doc jrd
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxWebFingerBody)).Decode(&doc); err != nil {
		return "", false
	}
	for _, l := range doc.Links {
		if l.Rel == oidcIssuerRel && l.Href != "" {
			return l.Href, true
		}
	}
	return "", false
}
