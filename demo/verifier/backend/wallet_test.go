package main

// Tests the wallet verification core against a mock OpenID Provider, offline.
// This exercises the real OpenPubkey verification path (VerifyPKToken +
// VerifySignedMessage) plus our email/issuer policy checks, without needing a
// live OP or network. It proves the server accepts a valid presentation and
// rejects tampered ones.

import (
	"context"
	"testing"

	"github.com/openpubkey/openpubkey/client"
	"github.com/openpubkey/openpubkey/providers"
	"github.com/openpubkey/openpubkey/providers/mocks"
	"github.com/openpubkey/openpubkey/verifier"
)

// newMockOP builds a mock OP whose issued ID tokens carry the given extra
// claims (e.g. an email), mirroring OpenPubkey's own verifier tests.
func newMockOP(t *testing.T, issuer, clientID string, extraClaims map[string]any) providers.OpenIdProvider {
	t.Helper()
	opts := providers.MockProviderOpts{
		Issuer:     issuer,
		Alg:        "RS256",
		ClientID:   clientID,
		GQSign:     false,
		NumKeys:    2,
		CommitType: providers.CommitTypesEnum.NONCE_CLAIM,
		VerifierOpts: providers.ProviderVerifierOpts{
			CommitType:        providers.CommitTypesEnum.NONCE_CLAIM,
			ClientID:          clientID,
			SkipClientIDCheck: false,
			GQOnly:            false,
		},
	}
	op, backend, _, err := providers.NewMockProvider(opts)
	if err != nil {
		t.Fatalf("new mock provider: %v", err)
	}
	signKey, keyID, rec := backend.RandomSigningKey()
	backend.SetIDTokenTemplate(&mocks.IDTokenTemplate{
		CommitFunc:  mocks.AddNonceCommit,
		Issuer:      op.Issuer(),
		Aud:         clientID,
		KeyID:       keyID,
		Alg:         rec.Alg,
		ExtraClaims: extraClaims,
		SigningKey:  signKey,
	})
	return op
}

// mintPresentation produces a valid (pkt, osm) for a challenge, plus a verifier
// that trusts the mock OP.
func mintPresentation(t *testing.T, email, challenge string) (*verifier.Verifier, string, string, string) {
	t.Helper()
	const clientID = "test_client_id"
	op := newMockOP(t, "https://mock.example.com", clientID, map[string]any{
		"aud":   clientID,
		"email": email,
	})

	opkClient, err := client.New(op)
	if err != nil {
		t.Fatalf("client.New: %v", err)
	}
	pkt, err := opkClient.Auth(context.Background())
	if err != nil {
		t.Fatalf("Auth: %v", err)
	}
	pktJSON, err := pkt.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal pkt: %v", err)
	}
	osm, err := pkt.NewSignedMessage([]byte(challenge), opkClient.GetSigner())
	if err != nil {
		t.Fatalf("sign challenge: %v", err)
	}
	v, err := verifier.New(op)
	if err != nil {
		t.Fatalf("verifier.New: %v", err)
	}
	return v, string(pktJSON), string(osm), op.Issuer()
}

func TestVerifyWalletPresentation(t *testing.T) {
	const email = "alice@example.com"
	const challenge = "server-challenge-123"
	v, pkt, osm, issuer := mintPresentation(t, email, challenge)

	trustMock := func(ctx context.Context, email, domain string) (string, string, bool) {
		return issuer, "test", true
	}
	ctx := context.Background()

	t.Run("valid presentation", func(t *testing.T) {
		res, verr := verifyWalletPresentation(ctx, v, trustMock, walletPresentation{
			Email: email, Challenge: challenge, PKT: pkt, OSM: osm,
		})
		if verr != nil {
			t.Fatalf("expected success, got: %v", verr)
		}
		if res.Email != email {
			t.Fatalf("email = %q, want %q", res.Email, email)
		}
		if res.Issuer != issuer {
			t.Fatalf("issuer = %q, want %q", res.Issuer, issuer)
		}
	})

	t.Run("wrong challenge is rejected", func(t *testing.T) {
		_, verr := verifyWalletPresentation(ctx, v, trustMock, walletPresentation{
			Email: email, Challenge: "not-the-challenge", PKT: pkt, OSM: osm,
		})
		if verr == nil {
			t.Fatal("expected rejection for wrong challenge")
		}
	})

	t.Run("wrong email is rejected", func(t *testing.T) {
		_, verr := verifyWalletPresentation(ctx, v, trustMock, walletPresentation{
			Email: "bob@example.com", Challenge: challenge, PKT: pkt, OSM: osm,
		})
		if verr == nil {
			t.Fatal("expected rejection for mismatched email")
		}
	})

	t.Run("untrusted issuer is rejected", func(t *testing.T) {
		trustOther := func(ctx context.Context, email, domain string) (string, string, bool) {
			return "https://someone-else.example.com", "test", true
		}
		_, verr := verifyWalletPresentation(ctx, v, trustOther, walletPresentation{
			Email: email, Challenge: challenge, PKT: pkt, OSM: osm,
		})
		if verr == nil {
			t.Fatal("expected rejection when issuer is not trusted for the domain")
		}
	})

	t.Run("no trusted issuer is rejected", func(t *testing.T) {
		trustNone := func(ctx context.Context, email, domain string) (string, string, bool) {
			return "", "", false
		}
		_, verr := verifyWalletPresentation(ctx, v, trustNone, walletPresentation{
			Email: email, Challenge: challenge, PKT: pkt, OSM: osm,
		})
		if verr == nil {
			t.Fatal("expected rejection when no issuer is trusted")
		}
	})

	t.Run("EBIA mode accepts any known issuer", func(t *testing.T) {
		// In EBIA mode authority comes from mailbox control, so the trust fn
		// returns the anyIssuer sentinel: any issuer the wallet verifier already
		// trusts is accepted, and the domain->issuer check is skipped.
		trustAny := func(ctx context.Context, email, domain string) (string, string, bool) {
			return anyIssuer, "ebia", true
		}
		res, verr := verifyWalletPresentation(ctx, v, trustAny, walletPresentation{
			Email: email, Challenge: challenge, PKT: pkt, OSM: osm,
		})
		if verr != nil {
			t.Fatalf("expected success in EBIA mode, got: %v", verr)
		}
		if res.Source != "ebia" {
			t.Fatalf("source = %q, want ebia", res.Source)
		}
	})

	t.Run("EBIA mode still requires matching email", func(t *testing.T) {
		trustAny := func(ctx context.Context, email, domain string) (string, string, bool) {
			return anyIssuer, "ebia", true
		}
		_, verr := verifyWalletPresentation(ctx, v, trustAny, walletPresentation{
			Email: "bob@example.com", Challenge: challenge, PKT: pkt, OSM: osm,
		})
		if verr == nil {
			t.Fatal("expected rejection: EBIA mode must still match the token email")
		}
	})

	t.Run("garbage pkt is rejected", func(t *testing.T) {
		_, verr := verifyWalletPresentation(ctx, v, trustMock, walletPresentation{
			Email: email, Challenge: challenge, PKT: "not json", OSM: osm,
		})
		if verr == nil {
			t.Fatal("expected rejection for malformed PK Token")
		}
	})
}
