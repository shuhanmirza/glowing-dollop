package main

// Discovery of a namespace domain's BYOID configuration.
//
// With no pre-binding, the Verifier learns how to authenticate a user by
// fetching a document the user's namespace domain serves at
// /.well-known/byoid-configuration. Serving it under the domain's origin is the
// authorization root (in production over TLS; the demo uses http on *.localhost,
// which Chrome treats as a secure context). The document may declare a blind
// relay the domain delegates to and the issuer that relay fronts.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

// byoidDiscoveryTimeout bounds the well-known fetch so login start stays
// responsive for domains that do not serve it.
const byoidDiscoveryTimeout = 4 * time.Second

// maxByoidBody caps how much we read from an untrusted domain's response.
const maxByoidBody = 64 * 1024

// byoidConfig is the subset of /.well-known/byoid-configuration we use.
type byoidConfig struct {
	Namespace string `json:"namespace"`
	Issuer    string `json:"issuer"`
	ClientID  string `json:"client_id"`
	// RelayRedirectURI is the exact redirect_uri the domain's blind relay has
	// registered with the OP. It must byte-match what the Verifier sends in the
	// authorization request and the token exchange.
	RelayRedirectURI string `json:"relay_redirect_uri"`
	Scopes           string `json:"scopes"`
	BindingMode      string `json:"binding_mode"`

	// Raw is the exact document the domain served (pretty-printed), kept so the
	// UI can show operators what discovery actually returned. Not re-serialized.
	Raw string `json:"-"`
}

// discoverByoidConfig fetches and parses the namespace domain's BYOID config.
// Returns ok=false if the domain serves nothing usable.
func discoverByoidConfig(ctx context.Context, domain string) (*byoidConfig, bool) {
	endpoint := url.URL{
		Scheme: "http", // demo: *.localhost. Production would be https.
		Host:   domain,
		Path:   "/.well-known/byoid-configuration",
	}

	ctx, cancel := context.WithTimeout(ctx, byoidDiscoveryTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxByoidBody))
	if err != nil {
		return nil, false
	}
	var cfg byoidConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return nil, false
	}
	// Keep the exact document (pretty-printed) for the UI's Details panel.
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		cfg.Raw = pretty.String()
	} else {
		cfg.Raw = string(body)
	}
	return &cfg, true
}

// hasRelayDelegation reports whether the config declares a usable blind-relay
// delegation (a registered redirect_uri, an issuer, and a client).
func (c *byoidConfig) hasRelayDelegation() bool {
	return c != nil && c.RelayRedirectURI != "" && c.Issuer != "" && c.ClientID != ""
}

// isPreBoundIssuer reports whether the Verifier already has a client binding
// with this issuer (so it would use its existing integration rather than a
// relay). Today the only pre-bound issuer is Google.
func isPreBoundIssuer(issuer string) bool {
	return issuer == googleIssuer
}
