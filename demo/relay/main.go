// Command relay is the BYOID blind relay ("relayoidc.localhost").
//
// It is the multi-tenant intermediary of the blind-relay scheme. A namespace owner
// (e.g. abc.localhost) delegates to this relay so its users can sign in to
// Verifiers it has no prior relationship with. The relay owns an OAuth client's
// registered redirect URI at the OP and relays the authorization code to the
// Verifier that started the flow.
//
// It is deliberately BLIND: with split-PKCE, the Verifier holds the
// code_verifier and redeems the code itself, so the relay never sees the token.
// The relay also never mints anything. Its whole job is to forward the code to
// the right Verifier, which it learns from the OAuth `state`.
//
// The routing `state` is a compact ES256 JWS the Verifier signs; the relay
// verifies it against the Verifier's published JWKS before relaying (see
// verify.go), so it will only relay to a callback whose domain proved it issued
// the request. Before relaying, the relay shows the user a consent page (see
// consent.go) stating which Verifier will receive the code and what it will
// learn.
//
// Flow: GET /cb (OP redirect) -> verify state -> render consent. The consent
// page POSTs to /relay, which re-verifies, consumes the single-use state, and
// redirects the browser to the Verifier's callback with the code.
package main

import (
	"log"
	"net/http"
	"net/url"
	"os"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", handleRoot)
	mux.HandleFunc("/cb", handleCallback)
	mux.HandleFunc("/relay", handleRelay)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	addr := ":" + port()
	log.Printf("[BYOID:relay] blind relay listening on %s (origin %s)", addr, relayOrigin())
	log.Fatal(http.ListenAndServe(addr, mux))
}

func port() string {
	if p := os.Getenv("PORT"); p != "" {
		return p
	}
	return "9090"
}

// handleCallback is the OP-registered redirect URI. The OP sends the browser
// here with ?code&state (or ?error). The relay authenticates the signed state,
// then shows a consent page before relaying. It never redeems the code — it
// holds no code_verifier (split-PKCE). This GET is idempotent: it verifies but
// does not consume the single-use state (that happens at /relay).
func handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rawState := q.Get("state")

	// An OP-side error: authenticate the routing state so we know where to send
	// it, then relay the error straight through to the Verifier.
	if e := q.Get("error"); e != "" {
		claims, err := verifyRoutingState(rawState, false)
		if err != nil {
			http.Error(w, "invalid state", http.StatusBadRequest)
			return
		}
		relayTo(w, r, claims.CB, map[string]string{
			"error":             e,
			"error_description": q.Get("error_description"),
			"state":             rawState,
		})
		return
	}

	claims, err := verifyRoutingState(rawState, false)
	if err != nil {
		log.Printf("[BYOID:relay] reject: %v", err)
		http.Error(w, "invalid or untrusted routing state", http.StatusBadRequest)
		return
	}
	code := q.Get("code")
	if code == "" {
		http.Error(w, "missing code", http.StatusBadRequest)
		return
	}

	log.Printf("[BYOID:relay] verified state → consent (verifier=%s op=%s sid=%s step=%v)",
		originOf(claims.CB), claims.OP, claims.SID, claims.Step)
	renderConsent(w, claims, code, rawState)
}

// handleRelay is the consent form target. It re-verifies the signed state,
// consumes the single-use jti, and redirects the browser to the Verifier
// callback with the code. Cancel is handled here too (decision=deny).
func handleRelay(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rawState := r.PostForm.Get("state")
	code := r.PostForm.Get("code")
	decision := r.PostForm.Get("decision")

	// Consume the single-use state here (state-changing action), so a reload of
	// the consent page (GET /cb) stays valid but a relay cannot be replayed.
	claims, err := verifyRoutingState(rawState, true)
	if err != nil {
		log.Printf("[BYOID:relay] relay reject: %v", err)
		http.Error(w, "invalid or untrusted routing state", http.StatusBadRequest)
		return
	}

	if decision != "allow" {
		log.Printf("[BYOID:relay] user declined → relay access_denied to %s", originOf(claims.CB))
		relayTo(w, r, claims.CB, map[string]string{
			"error": "access_denied",
			"state": rawState,
		})
		return
	}

	log.Printf("[BYOID:relay] consent granted → relay code (blind) to %s (sid=%s)",
		originOf(claims.CB), claims.SID)
	relayTo(w, r, claims.CB, map[string]string{
		"code":  code,
		"state": rawState,
	})
}

// relayTo redirects the browser to the Verifier callback with the given params
// merged onto any existing query.
func relayTo(w http.ResponseWriter, r *http.Request, cb string, params map[string]string) {
	u, err := url.Parse(cb)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		http.Error(w, "invalid callback", http.StatusBadRequest)
		return
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// originOf returns scheme://host of a URL for display/logging.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.Scheme + "://" + u.Host
}

// handleRoot serves the relay's landing page.
func handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(landingHTML))
}

const landingHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>relayoidc.localhost — Blind Relay</title>
<style>
  :root { --bg:#12091f; --accent:#b06bff; --ink:#ece7f5; }
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; font-family:"Segoe UI",system-ui,sans-serif;
    background:var(--bg); background-image:radial-gradient(circle at 20% 20%,#2a1650 0%,var(--bg) 60%);
    color:var(--ink); display:flex; align-items:center; justify-content:center; padding:32px; }
  .card { max-width:600px; background:rgba(30,18,54,0.85); border:1px solid #3a2560;
    border-radius:16px; padding:40px 44px; box-shadow:0 20px 60px rgba(0,0,0,0.5); }
  .badge { display:inline-flex; align-items:center; gap:8px; font-size:12px; letter-spacing:0.12em;
    text-transform:uppercase; color:var(--accent); border:1px solid #4a2f7a; border-radius:999px; padding:6px 14px; }
  .dot { width:8px; height:8px; border-radius:50%; background:#7ee0a0; box-shadow:0 0 0 3px rgba(126,224,160,0.2); }
  h1 { margin:16px 0 6px; font-size:32px; }
  .mono { font-family:"Courier New",monospace; color:var(--accent); }
  p { line-height:1.65; color:#c8bce0; }
  .flow { margin-top:22px; padding:16px 18px; background:#1b0f33; border:1px solid #3a2560; border-radius:10px;
    font-family:"Courier New",monospace; font-size:13px; color:#d9ccf5; }
  .blind { margin-top:18px; font-size:14px; color:#9d8fc0; }
  b { color:#fff; }
</style>
</head>
<body>
  <div class="card">
    <span class="badge"><span class="dot"></span> Blind Relay · live</span>
    <h1><span class="mono">relayoidc.localhost</span></h1>
    <p>
      A multi-tenant <b>blind relay</b>. Namespace owners delegate to it so their
      users can sign in to Verifiers they have no prior relationship with. It
      owns an OP-registered redirect URI and forwards the authorization code to
      the Verifier that started the flow.
    </p>
    <div class="flow">OP ──code──▶ relayoidc.localhost/cb ──code──▶ Verifier</div>
    <p class="blind">
      🔒 <b>Blind by construction.</b> With split-PKCE the Verifier holds the
      <span class="mono">code_verifier</span> and redeems the code itself, so
      this relay never sees the token — it only relays.
    </p>
  </div>
</body>
</html>`
