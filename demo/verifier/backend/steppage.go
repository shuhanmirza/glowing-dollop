package main

// Server-rendered interstitial pages for the "step-by-step" relay demo.
//
// In step-by-step mode the split-PKCE flow pauses at each protocol hop and
// renders one of these pages (with a "Next" button) so the audience can see
// exactly what is exchanged: the OP authorization request, the blind relay's
// relay, the Verifier's token request, and the token it receives. Each page is
// served by the actor that actually performs that step (the Verifier here; the
// blind relay renders its own), so the browser's address bar reinforces who is
// doing what.

import (
	"html/template"
	"net/http"

	"github.com/gin-gonic/gin"
)

// stepRow is one key/value line in a step block.
type stepRow struct {
	K    string
	V    string
	Note string // optional dimmed annotation under the value
	Mono bool   // render the value in monospace (URLs, tokens, hashes)
}

// stepBlock is a titled group of rows, or a preformatted code blob.
type stepBlock struct {
	Heading string
	Rows    []stepRow
	Code    string // if set, rendered as a <pre> instead of Rows
}

// stepView is the data for one interstitial page.
type stepView struct {
	Actor     string // who is rendering this page, e.g. "xyz.com · Verifier"
	Accent    string // accent color (hex)
	Progress  string // e.g. "Step 1 of 4"
	Title     string
	Subtitle  template.HTML
	Blocks    []stepBlock
	NextURL   string
	NextLabel string
	NextNote  string // dimmed note under the Next button
}

// renderStepPage writes a step interstitial as an HTML response.
func renderStepPage(c *gin.Context, v stepView) {
	if v.Accent == "" {
		v.Accent = "#4f46e5"
	}
	if v.NextLabel == "" {
		v.NextLabel = "Next →"
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = stepTmpl.Execute(c.Writer, v)
}

var stepTmpl = template.Must(template.New("step").Parse(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Progress}} — {{.Title}}</title>
<style>
  :root { --accent: {{.Accent}}; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; background:#f4f5fb; color:#1c2036;
    font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
    display:flex; align-items:center; justify-content:center; padding:32px; }
  .card { width:100%; max-width:620px; background:#fff; border:1px solid #e3e5f0;
    border-radius:16px; padding:34px 36px; box-shadow:0 18px 50px rgba(30,34,70,.10); }
  .actor { display:inline-flex; align-items:center; gap:8px; font-size:12px; font-weight:700;
    letter-spacing:.08em; text-transform:uppercase; color:var(--accent);
    border:1px solid var(--accent); border-radius:999px; padding:5px 13px; opacity:.9; }
  .progress { margin-top:16px; font-size:13px; font-weight:600; color:#8a90ad; letter-spacing:.04em; }
  h1 { margin:4px 0 8px; font-size:25px; line-height:1.2; }
  .subtitle { margin:0 0 22px; font-size:15px; line-height:1.6; color:#565d7e; }
  .block { border:1px solid #e8eaf3; border-radius:12px; padding:16px 18px; margin-bottom:14px; background:#fafbff; }
  .block h2 { margin:0 0 12px; font-size:12px; font-weight:700; text-transform:uppercase;
    letter-spacing:.07em; color:#8a90ad; }
  .row { display:grid; grid-template-columns:170px 1fr; gap:12px; padding:6px 0;
    border-top:1px solid #eef0f8; }
  .row:first-of-type { border-top:none; }
  .row .k { font-size:13px; color:#6b7194; font-weight:600; }
  .row .v { font-size:14px; word-break:break-all; }
  .row .v.mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:13px; color:#1c2036; }
  .row .note { display:block; margin-top:3px; font-size:12px; color:#9aa0bd; }
  pre { margin:0; padding:14px; background:#0f1330; color:#c9d2ff; border-radius:10px;
    font-family:ui-monospace,SFMono-Regular,Menlo,monospace; font-size:12.5px; line-height:1.5;
    overflow:auto; max-height:300px; }
  .next { display:inline-block; margin-top:10px; background:var(--accent); color:#fff;
    text-decoration:none; font-size:15px; font-weight:600; padding:13px 26px; border-radius:10px; }
  .next:hover { filter:brightness(1.07); }
  .nextnote { margin-top:10px; font-size:12.5px; color:#9aa0bd; }
</style></head>
<body>
  <div class="card">
    <span class="actor">{{.Actor}}</span>
    <div class="progress">{{.Progress}}</div>
    <h1>{{.Title}}</h1>
    <p class="subtitle">{{.Subtitle}}</p>
    {{range .Blocks}}
    <div class="block">
      <h2>{{.Heading}}</h2>
      {{if .Code}}<pre>{{.Code}}</pre>{{else}}
        {{range .Rows}}
        <div class="row">
          <div class="k">{{.K}}</div>
          <div class="v {{if .Mono}}mono{{end}}">{{.V}}{{if .Note}}<span class="note">{{.Note}}</span>{{end}}</div>
        </div>
        {{end}}
      {{end}}
    </div>
    {{end}}
    <a class="next" href="{{.NextURL}}">{{.NextLabel}}</a>
    {{if .NextNote}}<div class="nextnote">{{.NextNote}}</div>{{end}}
  </div>
</body></html>`))
