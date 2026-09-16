package main

// The consent page the blind relay shows before relaying the code.
//
// It runs on every relay login (always on). Because the relay is blind it does
// not know the user's identity or token. It can state the callback with full
// authority: the routing state is signed by the Verifier and the callback is
// required to be same-origin as the signer, so "the code goes to <verifier>" is
// cryptographically proven. The OP and scopes shown, however, are read from the
// Verifier's signed state: they are authenticated as the Verifier's *own
// statement*, not independently verified. The blind relay never sees the OP
// exchange, so it cannot confirm the user actually authenticated at that OP or
// that those are the exact granted scopes. When the flow is in step-by-step
// mode the page doubles as "Step 2 of 4" and adds the technical detail of what
// was received and where it will be relayed.

import (
	"html/template"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// stateClaim is one decoded, verified claim from the signed routing state,
// shown so the user can see exactly what the relay verified and is acting on.
type stateClaim struct {
	Key  string
	Val  string
	Note string
}

// consentView is the data for the consent page.
type consentView struct {
	VerifierOrigin string   // scheme://host the code is relayed to
	OP             string   // OP issuer that authenticated the user
	Scopes         []string // scopes the Verifier will obtain
	Step           bool     // step-by-step demo (adds technical detail)
	Code           string   // authorization code (echoed in the relay form; also displayed in step mode)
	State          string   // signed routing state (echoed in the form)

	// Verification metadata: how the relay authenticated this routing request.
	SignerHost string // callback host whose published key signed the state
	JWKSURL    string // well-known endpoint the public key came from
	KID        string // key id used to verify
	Alg        string // signature algorithm

	// StateClaims spells out the decoded, verified routing state.
	StateClaims []stateClaim
}

func renderConsent(w http.ResponseWriter, claims *routingClaims, code, rawState string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	base := originOf(claims.CB)
	vi := routingVerification(base, rawState)
	v := consentView{
		VerifierOrigin: base,
		OP:             hostOnly(claims.OP),
		Scopes:         splitScopes(claims.Scope),
		Step:           claims.Step,
		Code:           code,
		State:          rawState,
		SignerHost:     vi.SignerHost,
		JWKSURL:        vi.JWKSURL,
		KID:            vi.KID,
		Alg:            vi.Alg,
		StateClaims:    decodeStateForDisplay(claims),
	}
	_ = consentTmpl.Execute(w, v)
}

// decodeStateForDisplay turns the verified claims into readable rows, in the
// order they appear in the signed token, with unix times rendered human-legibly.
func decodeStateForDisplay(c *routingClaims) []stateClaim {
	rows := []stateClaim{
		{Key: "aud", Val: c.Aud, Note: "the intended relay (this one)"},
		{Key: "cb", Val: c.CB, Note: "where the code is relayed"},
		{Key: "sid", Val: c.SID, Note: "the Verifier's session id"},
		{Key: "op", Val: c.OP, Note: "the OpenID Provider"},
		{Key: "scope", Val: c.Scope, Note: "what the Verifier will obtain"},
		{Key: "jti", Val: c.JTI, Note: "single-use id (blocks replay)"},
		{Key: "iat", Val: fmtUnix(c.IAT), Note: "issued at"},
		{Key: "exp", Val: fmtUnix(c.EXP), Note: "expires"},
	}
	if c.Step {
		rows = append(rows, stateClaim{Key: "step", Val: "true", Note: "step-by-step demo"})
	}
	return rows
}

// fmtUnix renders a unix timestamp as "unix (RFC3339 UTC)", or "-" if zero.
func fmtUnix(ts int64) string {
	if ts == 0 {
		return "-"
	}
	return strconv.FormatInt(ts, 10) + " (" + time.Unix(ts, 0).UTC().Format(time.RFC3339) + ")"
}

func hostOnly(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Host
}

func splitScopes(s string) []string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return []string{"openid"}
	}
	return fields
}

// scopeMeaning gives a human phrase for the common OIDC scopes.
func scopeMeaning(scope string) string {
	switch scope {
	case "openid":
		return "confirm you signed in"
	case "email":
		return "your email address"
	case "profile":
		return "your basic profile (name, picture)"
	default:
		return scope
	}
}

var consentTmpl = template.Must(template.New("consent").Funcs(template.FuncMap{
	"meaning": scopeMeaning,
}).Parse(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Confirm sign-in — Blind relay</title>
<style>
  * { box-sizing:border-box; }
  body { margin:0; min-height:100vh; font-family:"Segoe UI",system-ui,sans-serif;
    background:#12091f; background-image:radial-gradient(circle at 20% 15%,#2a1650 0%,#12091f 60%);
    color:#ece7f5; display:flex; align-items:center; justify-content:center; padding:32px; }
  .card { width:100%; max-width:600px; background:rgba(30,18,54,.92); border:1px solid #3a2560;
    border-radius:16px; padding:32px 34px; box-shadow:0 20px 60px rgba(0,0,0,.5); }
  .actor { display:inline-flex; align-items:center; gap:8px; font-size:12px; font-weight:700;
    letter-spacing:.08em; text-transform:uppercase; color:#b06bff; border:1px solid #4a2f7a;
    border-radius:999px; padding:5px 13px; }
  .dot { width:8px; height:8px; border-radius:50%; background:#7ee0a0; box-shadow:0 0 0 3px rgba(126,224,160,.2); }
  .progress { margin-top:14px; font-size:13px; font-weight:600; color:#9d8fc0; letter-spacing:.04em; }
  h1 { margin:6px 0 6px; font-size:23px; line-height:1.25; color:#fff; }
  .lede { margin:0 0 20px; font-size:15px; line-height:1.6; color:#c8bce0; }
  .grant { border:1px solid #3a2560; border-radius:12px; padding:18px 20px; margin-bottom:16px; background:#1b0f33; }
  .to { display:flex; align-items:baseline; gap:8px; font-size:15px; margin-bottom:6px; }
  .to .who { font-weight:700; color:#fff; font-family:ui-monospace,Menlo,monospace; }
  .via { font-size:13px; color:#9d8fc0; margin-bottom:16px; }
  .via code { color:#e5b8ff; }
  .learn { font-size:13px; font-weight:700; text-transform:uppercase; letter-spacing:.06em;
    color:#9d8fc0; margin:0 0 10px; }
  ul { margin:0; padding:0; list-style:none; }
  li { display:flex; gap:10px; align-items:flex-start; padding:6px 0; font-size:14px; color:#e6dcff; }
  li .s { font-family:ui-monospace,Menlo,monospace; color:#b06bff; min-width:74px; }
  li .m { color:#c8bce0; }
  details { margin:4px 0 18px; }
  summary { cursor:pointer; font-size:13px; color:#b06bff; }
  .tech { margin-top:12px; }
  .tech .block { border:1px solid #3a2560; border-radius:10px; padding:12px 14px; margin-bottom:10px; background:#160a26; }
  .tech .block h2 { margin:0 0 8px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.07em; color:#9d8fc0; }
  .tech .row { display:grid; grid-template-columns:110px 1fr; gap:10px; font-size:12.5px; padding:4px 0; }
  .tech .k { color:#9d8fc0; font-weight:600; }
  .tech .v { font-family:ui-monospace,Menlo,monospace; color:#e6dcff; word-break:break-all; }
  .blind { margin:0 0 20px; padding:12px 14px; background:#160a26; border:1px dashed #4a2f7a;
    border-radius:10px; font-size:13px; color:#c8bce0; }
  .blind b { color:#fff; }
  .verified { margin:0 0 16px; padding:14px 16px; border-radius:12px;
    background:rgba(126,224,160,.08); border:1px solid #2f6b4a; }
  .verified .vhead { display:flex; align-items:center; gap:9px; font-size:14px; font-weight:700; color:#7ee0a0; }
  .verified .vcheck { display:inline-flex; align-items:center; justify-content:center; width:20px; height:20px;
    border-radius:50%; background:#7ee0a0; color:#0d2a1a; font-size:13px; font-weight:900; }
  .verified .vsub { margin:4px 0 10px 29px; font-size:12.5px; color:#a9cbb8; }
  .verified .vrow { display:grid; grid-template-columns:96px 1fr; gap:10px; padding:3px 0 3px 29px; font-size:12.5px; }
  .verified .vk { color:#8fb9a3; font-weight:600; }
  .verified .vv { font-family:ui-monospace,Menlo,monospace; color:#d7f2e2; word-break:break-all; }
  .state { margin:0 0 16px; border:1px solid #3a2560; border-radius:12px; background:#160a26; overflow:hidden; }
  .state summary { cursor:pointer; padding:12px 16px; font-size:13px; font-weight:700; color:#c8bce0;
    list-style:none; display:flex; align-items:center; gap:8px; }
  .state summary::-webkit-details-marker { display:none; }
  .state summary .chev { color:#b06bff; transition:transform .15s; }
  .state[open] summary .chev { transform:rotate(90deg); }
  .state summary .tag { margin-left:auto; font-weight:600; font-size:11px; text-transform:uppercase;
    letter-spacing:.06em; color:#7ee0a0; }
  .state .body { padding:2px 16px 14px; }
  .state .caption { font-size:12px; color:#9d8fc0; margin:0 0 10px; }
  .srow { display:grid; grid-template-columns:64px 1fr; gap:10px; padding:5px 0; border-top:1px solid #241542; }
  .srow:first-of-type { border-top:none; }
  .srow .sk { font-family:ui-monospace,Menlo,monospace; color:#b06bff; font-size:12.5px; }
  .srow .sv { font-family:ui-monospace,Menlo,monospace; color:#e6dcff; font-size:12.5px; word-break:break-all; }
  .srow .sn { display:block; margin-top:2px; font-family:"Segoe UI",system-ui,sans-serif; color:#8a7caa; font-size:11.5px; }
  .actions { display:flex; gap:12px; }
  form { margin:0; flex:1; }
  button { width:100%; font:inherit; font-size:15px; font-weight:700; padding:13px 20px; border-radius:10px;
    border:1px solid transparent; cursor:pointer; }
  .allow { background:#b06bff; color:#160a26; }
  .allow:hover { filter:brightness(1.08); }
  .deny { background:transparent; color:#c8bce0; border-color:#3a2560; }
  .deny:hover { background:#1b0f33; }
</style></head>
<body>
  <div class="card">
    <span class="actor"><span class="dot"></span> relayoidc.localhost · Blind Relay</span>
    {{if .Step}}<div class="progress">Step 2 of 4</div>{{end}}
    <h1>Continue signing in?</h1>
    <p class="lede">You authenticated with your identity provider. This blind relay is about
      to hand the login result to the site you're signing in to. It never sees your token.</p>

    <div class="verified">
      <div class="vhead"><span class="vcheck">&check;</span> Request signature verified</div>
      <div class="vsub">This sign-in request was signed by the site and checked against the public
        key it publishes — so this relay is genuinely acting for it.</div>
      <div class="vrow"><span class="vk">signed by</span><span class="vv">{{.SignerHost}}</span></div>
      <div class="vrow"><span class="vk">public key</span><span class="vv">{{.JWKSURL}}</span></div>
      <div class="vrow"><span class="vk">algorithm</span><span class="vv">{{.Alg}}{{if .KID}} · kid {{.KID}}{{end}}</span></div>
    </div>

    <details class="state"{{if .Step}} open{{end}}>
      <summary><span class="chev">&#9656;</span> Signed state (decoded &amp; verified) <span class="tag">what was signed</span></summary>
      <div class="body">
        <p class="caption">These are the exact claims inside the signed token above — the payload the
          relay verified against {{.SignerHost}}'s public key and is now acting on.</p>
        {{range .StateClaims}}
        <div class="srow">
          <span class="sk">{{.Key}}</span>
          <span class="sv">{{.Val}}<span class="sn">{{.Note}}</span></span>
        </div>
        {{end}}
      </div>
    </details>

    <div class="grant">
      <div class="to"><span>Signing in to</span> <span class="who">{{.VerifierOrigin}}</span></div>
      <div class="via">authenticated by <code>{{.OP}}</code> · relayed by relayoidc.localhost</div>
      <p class="learn">{{.VerifierOrigin}} will learn</p>
      <ul>
        {{range .Scopes}}<li><span class="s">{{.}}</span> <span class="m">{{meaning .}}</span></li>{{end}}
      </ul>
    </div>

    {{if .Step}}
    <div class="tech">
      <div class="block">
        <h2>What the relay received from the OP</h2>
        <div class="row"><div class="k">code</div><div class="v">{{.Code}}</div></div>
      </div>
      <div class="block">
        <h2>Where it will relay</h2>
        <div class="row"><div class="k">→ callback</div><div class="v">{{.VerifierOrigin}}/api/relay/callback</div></div>
      </div>
    </div>
    {{end}}

    <p class="blind">🔒 <b>Blind by construction.</b> The relay holds the authorization
      <code>code</code> but not the PKCE <code>code_verifier</code> — only {{.VerifierOrigin}}
      can redeem it. The relay cannot see your token.</p>

    <div class="actions">
      <form method="POST" action="/relay">
        <input type="hidden" name="state" value="{{.State}}">
        <input type="hidden" name="code" value="{{.Code}}">
        <input type="hidden" name="decision" value="deny">
        <button class="deny" type="submit">Cancel</button>
      </form>
      <form method="POST" action="/relay">
        <input type="hidden" name="state" value="{{.State}}">
        <input type="hidden" name="code" value="{{.Code}}">
        <input type="hidden" name="decision" value="allow">
        <button class="allow" type="submit">Continue &rarr;</button>
      </form>
    </div>
  </div>
</body></html>`))
