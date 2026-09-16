# Bring Your Own IdP Identity

Authenticate a user from an identity provider (OP) you have **never met** — with
**no change to the OP** — by routing trust through a binding that already exists.

A service (`xyz.com`) usually can only accept an identity like
`alice@abc.com` after it has pre-registered as a client of Alice's OP. That
pre-binding does not scale to the open internet, and the standards meant to
automate it (Dynamic Client Registration, OpenID Federation) are not adopted by
the consumer OPs users actually bring. This project shows how to bridge that gap
*today*, requiring implementation only from the parties who benefit — the service
and either the **user** or the user's **org** — and nothing from the OP.

We call the approach **delegated attestation**, and it comes in two flavors:

- **Identity wallet** — software the *user* runs (an OpenPubkey-style local
  agent) that carries an OP-signed credential and presents it with a
  proof-of-possession. Implemented here as a browser extension.
- **Blind OIDC relay** — a multi-tenant intermediary the user's *org* delegates.
  Using a split of the PKCE exchange, it forwards the OP's authorization code but
  can never redeem it, so it never sees the user's token — hence "blind."



## Repository layout

```
.
├── demo/                runnable end-to-end demo (docker compose)
│   ├── op/              demo OpenID Provider (Dex)               → op/README.md
│   ├── abc/             demo namespace domain + delegation doc   → abc/README.md
│   ├── relay/           the blind OIDC relay                    → relay/README.md
│   ├── extension/       the identity wallet, a browser extension → extension/README.md
│   ├── verifier/        the Verifier — Go backend + Vue frontend
│   └── README.md        how to run the whole demo               → demo/README.md
└── openid-fed-survey/   survey of which OPs actually implement OpenID Federation
```

## Where to start

- **Run the demo:** [`demo/README.md`](./demo/README.md) — one `docker compose up`
  brings up the OP, the namespace domain, the blind relay, and the Verifier.
- **Understand a component:** each service has its own README —
  [`demo/op`](./demo/op/README.md), [`demo/abc`](./demo/abc/README.md),
  [`demo/relay`](./demo/relay/README.md),
  [`demo/extension`](./demo/extension/README.md).
- **See the adoption evidence:** [`openid-fed-survey/`](./openid-fed-survey) —
  `main.py` probes a list of OPs; `results.csv` holds the verdicts.

## Terminology

| Term | Meaning |
|------|---------|
| **OP** | OpenID Provider — the identity provider that authenticates the user and signs tokens. Unmodified in this work. |
| **Verifier** | The service the user signs in to. Deliberately *not* a pre-registered client of the OP. |
| **Org** | The organization that owns the user's namespace (e.g. `abc.com`) and vouches for its members. May differ from the OP. |
| **Identity wallet** | User-run agent that carries an OP-signed credential. |
| **Blind OIDC relay** | Org-delegated, token-blind intermediary that relays the auth code. |

## Testing the Authentication Flows

Once the local demonstration environment is running, you can test both the Blind OIDC Relay and Identity Wallet constructions. The frontend Verifier (running at http://localhost:5173) uses identifier-first routing to dynamically select the correct flow based on the entered email address.

### Flow 1: Blind OIDC Relay (Split-PKCE)

This flow demonstrates an organization delegating its OIDC client registration to a centralized relay using standard browser redirects.

1.  **Initiate Login:** Navigate to the Verifier at http://localhost:5173.
    
2.  **Enter Test Identity:** Enter the relay-configured test email: alice@abc.localhost and click **Next**.
    
3.  **Inspect the Configuration (Optional):** The Verifier will fetch the organization's WebFinger configuration. You can toggle **"Step-by-step demo"** ON to pause the flow at each network hop and inspect the underlying cryptographic parameters (e.g., the Signed State JWT and PKCE challenges).
    
4.  **Authenticate at the OP:** Click **Continue through the blind relay**. You will be redirected to the mock OpenID Provider (Dex). Log in using the test credentials (alice@abc.localhost / password).
    
5.  **Relay Handoff:** The OP redirects your browser to the Blind Relay (relayoidc.localhost). The Relay cryptographically verifies the Verifier's signed state. Click **Continue** to approve the code handoff.
    
6.  **Token Redemption:** The Relay forwards the authorization code back to the Verifier. If you enabled the step-by-step mode, click **Exchange the code** to watch the Verifier combine the code with its secret code\_verifier to redeem the ID token and finalize the login.
    

### Flow 2: Identity Wallet (Proof-of-Possession)

This flow demonstrates a user authenticating via a local browser extension that holds a public key-bound ID token (PK Token).

_Note: Ensure the demonstration browser extension is loaded into your browser before starting._

1.  **Initiate Login:** Navigate to the Verifier at http://localhost:5173.
    
2.  **Enter a Live Identity:** Enter a real email address you control (e.g., a test Google or Microsoft account) and click **Next**.
    
3.  **Bootstrap Trust (EBIA Fallback):** Because this domain lacks a WebFinger delegation record, the Verifier falls back to an email challenge. Click **Open the verification link** to simulate mailbox control.
    
4.  **Invoke the Wallet:** Once verified, click **BYOID PK Token Wallet**.
    
5.  **Credential Enrollment:** The browser extension will open and prompt you to add the identity. Select the corresponding provider (e.g., Google or Microsoft) and complete the standard OAuth login. The provider will issue an ID token cryptographically bound to a keypair generated inside the extension.
    
6.  **Presentation & Success:** Once the identity is added, the extension will seamlessly sign the Verifier's fresh challenge (Proof-of-Possession). The Verifier validates this signature and grants access.
    
7.  **Inspect the Token (Optional):** You can open the browser extension popup at any time to inspect the raw structure of the generated PK Token, including the Client Instance Claims (CIC), OpenPubkey signatures, and the decoded OP token claims.