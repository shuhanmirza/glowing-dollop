package main

// Email-Based Identity Assertion (EBIA) fallback.
//
// When the Verifier cannot establish a trusted domain->issuer relationship for
// the user's email (no WebFinger declaration and no known provider binding), it
// falls back to proving control of the mailbox itself: the classic "click the
// link we emailed you" flow. Authority is rooted in mailbox control at the
// namespace domain -- the same anchor as our email challenge throughout.
//
// In a real deployment the Verifier would email this magic link to the user.
// For the demo we do NOT send email; instead the link is returned to the
// frontend and shown to the user to click.
//
// Visiting the magic link proves mailbox control, which is itself the trust
// this case needs. We therefore turn the one-time link into a short-lived
// "EBIA session" and send the user back to the Verifier frontend, where they
// can complete sign-in with their identity wallet (see wallet.go: an EBIA
// session lets the wallet check skip the domain->issuer requirement, because
// mailbox control -- not a domain declaration -- carries the authority here).

import (
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

// ebiaTTL bounds how long a magic link stays valid.
const ebiaTTL = 30 * time.Minute

// ebiaSessionTTL bounds how long a proven-mailbox session stays usable for a
// wallet sign-in after the magic link is clicked.
const ebiaSessionTTL = 15 * time.Minute

// ebiaChallenge ties a magic-link token to the email being verified.
type ebiaChallenge struct {
	email   string
	created time.Time
}

// ebiaSession represents mailbox control that has been proven (the magic link
// was visited) and can now back a wallet sign-in for that email.
type ebiaSession struct {
	email   string
	created time.Time
}

var (
	ebiaMu         sync.Mutex
	ebiaChallenges = map[string]*ebiaChallenge{}
	ebiaSessions   = map[string]*ebiaSession{}
)

// backendPublicURL is the base URL the user's browser can reach this backend
// at; the magic link must be clickable from the browser. It defaults to the
// published demo port and can be overridden for other setups.
func backendPublicURL() string {
	if v := os.Getenv("BACKEND_PUBLIC_URL"); v != "" {
		return v
	}
	return "http://localhost:11110"
}

// newEBIAChallenge creates a magic-link token for the given email and returns
// the full link to show to the user.
func newEBIAChallenge(email string) (string, error) {
	token, err := randomToken(32)
	if err != nil {
		return "", err
	}
	ebiaMu.Lock()
	gcEBIA()
	ebiaChallenges[token] = &ebiaChallenge{email: email, created: time.Now()}
	ebiaMu.Unlock()
	return backendPublicURL() + "/ebia/verify?token=" + token, nil
}

// gcEBIA drops expired challenges and sessions. Caller must hold ebiaMu.
func gcEBIA() {
	now := time.Now()
	for k, v := range ebiaChallenges {
		if now.Sub(v.created) > ebiaTTL {
			delete(ebiaChallenges, k)
		}
	}
	for k, v := range ebiaSessions {
		if now.Sub(v.created) > ebiaSessionTTL {
			delete(ebiaSessions, k)
		}
	}
}

// handleEBIAVerify consumes a single-use magic-link token, records that mailbox
// control was proven (an EBIA session), and redirects the user back to the
// Verifier frontend to finish signing in with their wallet.
func handleEBIAVerify(c *gin.Context) {
	token := c.Query("token")

	ebiaMu.Lock()
	ch := ebiaChallenges[token]
	if ch != nil {
		delete(ebiaChallenges, token)
	}
	ebiaMu.Unlock()

	if ch == nil || time.Since(ch.created) > ebiaTTL {
		// Bounce back to the frontend with an error to display.
		c.Redirect(http.StatusFound, frontendURL()+"/?ebia_error=expired")
		return
	}

	// Mint an EBIA session (mailbox control proven) and hand it to the frontend.
	sid, err := randomToken(32)
	if err != nil {
		c.Redirect(http.StatusFound, frontendURL()+"/?ebia_error=server_error")
		return
	}
	ebiaMu.Lock()
	gcEBIA()
	ebiaSessions[sid] = &ebiaSession{email: ch.email, created: time.Now()}
	ebiaMu.Unlock()

	c.Redirect(http.StatusFound, frontendURL()+"/?ebia="+sid)
}

// handleEBIAInfo returns the email a valid EBIA session was verified for, so
// the frontend can show it. It does not consume the session.
func handleEBIAInfo(c *gin.Context) {
	sid := c.Query("session")
	ebiaMu.Lock()
	s := ebiaSessions[sid]
	ebiaMu.Unlock()
	if s == nil || time.Since(s.created) > ebiaSessionTTL {
		c.JSON(http.StatusNotFound, errorResponse{Error: "EBIA session expired or unknown"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"email": s.email, "verified": true})
}

// consumeEBIASession validates and consumes an EBIA session for the given
// email, returning true if mailbox control was proven for that email.
func consumeEBIASession(sid, email string) bool {
	ebiaMu.Lock()
	defer ebiaMu.Unlock()
	s := ebiaSessions[sid]
	if s == nil || time.Since(s.created) > ebiaSessionTTL {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(s.email), strings.TrimSpace(email)) {
		return false
	}
	delete(ebiaSessions, sid)
	return true
}
