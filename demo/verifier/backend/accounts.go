package main

// localAccounts holds demo users that have a username/password account with
// the Verifier itself. This is the case where the Verifier can authenticate
// the user on its own, without involving any external identity provider.
//
// In a real system this would be a database of salted password hashes; for the
// demo it is a hard-coded map. Keys are lower-cased email addresses.
var localAccounts = map[string]string{
	"alice@xyz.com": "password123",
}

// localPassword returns the stored password for a local account and whether an
// account exists for the given (already normalized) email.
func localPassword(email string) (string, bool) {
	pw, ok := localAccounts[email]
	return pw, ok
}

// googleBoundDomains are email domains for which the Verifier already has an
// OIDC client binding with Google, so users at these domains can sign in with
// "Continue with Google". In the demo we treat consumer Google Mail domains as
// bound; a real deployment would list the Workspace domains it has onboarded.
var googleBoundDomains = map[string]bool{
	"gmail.com":      true,
	"googlemail.com": true,
}

// isGoogleBoundDomain reports whether the domain can sign in via Google.
func isGoogleBoundDomain(domain string) bool {
	return googleBoundDomains[domain]
}
