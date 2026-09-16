# Demo

Runnable demos for the Bring-Your-Own-IdP project.

## Demo OpenID Provider (`op.localhost`)

A minimal, unmodified [Dex](https://dexidp.io) OP used to demonstrate that the
wallet mints PK tokens against a real provider the project does not control. It
hosts one public PKCE client (`byoid-demo`) and one demo user
(`alice@abc.localhost` / `password123`) in the `abc.localhost` namespace. Issuer:
`http://op.localhost:5556`.

```sh
docker compose up op        # from demo/
```

In Chrome no host setup is needed — it resolves `*.localhost` to loopback and
treats it as a secure context. Full details, other-browser notes, and the
`/etc/hosts` fallback are in [`op/README.md`](./op/README.md).

## Blind relay (`abc.localhost` + `relayoidc.localhost`)

Two more services demonstrate the blind-relay flow, in which a Verifier authenticates
a user from a domain it has never met, whose OP it has no binding with, via a
**blind relay** the domain delegates:

- **`abc.localhost`** — a demo namespace domain. Serves a distinct landing page
  and publishes `/.well-known/byoid-configuration` (issuer + org client +
  delegated relay). Authorization root: the doc is served from the domain
  itself. See [`abc/README.md`](./abc/README.md).
- **`relayoidc.localhost`** — the untrusted, multi-tenant **blind relay**. Owns
  the OP-registered redirect URI and relays the auth code to the Verifier; it
  never redeems the code (split-PKCE) so never sees the token. See
  [`relay/README.md`](./relay/README.md).

Flow: enter `alice@abc.localhost` at the Verifier → it fetches
`abc.localhost`'s config, sees a delegated relay for an issuer it is not
pre-bound to → offers **"Continue through abc.localhost's relay"** → standard
OIDC + PKCE where the relay relays the code and the Verifier redeems it. The OP
is the same demo Dex (`op.localhost`), using a second public client
(`byoid-relay-client`) whose redirect URI is the relay's.

## Verifier

The Verifier is the Relying Party (SP) that wants to authenticate a user. The
sign-in flow is **identifier-first**: the page collects the user's **email**
and a **Next** button, and the backend decides how to authenticate them based
on the email (`POST /api/login/start` returns a `method`):

- **`password`** — the user has a local username/password account with the
  Verifier itself. Demo account: `alice@xyz.com` / `password123`. Step 2 prompts
  for the password (`POST /api/login/password`).
- **`oauth`** — the user's domain is served by a provider the Verifier already
  has a client binding with. In the demo, `@gmail.com` (and `@googlemail.com`)
  resolve to **Continue with Google**, which runs a real OpenID Connect
  authorization-code flow (with PKCE) against Google and verifies the returned
  ID token. The trust cue shows the relationship as established `via
  known-provider`. See "Google login" below.
- **`trust`** — with no pre-binding, the Verifier asks the user's namespace
  domain (over HTTPS) which issuer it authorizes, by fetching its **WebFinger**
  declaration: `GET https://<domain>/.well-known/webfinger?resource=acct:<email>
  &rel=http://openid.net/specs/connect/1.0/issuer`. Because the response is
  fetched directly from the domain over TLS, serving it *is* proof of control
  over that domain — so this is the **namespace owner's** authorization
  statement, not the issuer's self-claim, and the issuer (OP) is never asked to
  declare anything. If the domain declares an issuer, the second page shows a
  trust cue (`via webfinger`). Note: almost no public domain serves WebFinger
  today, so real arbitrary domains will fall through to `ebia` (see
  `webfinger_test.go` for the positive path).
- **`ebia`** — no trusted domain→issuer relationship could be established. The
  Verifier falls back to **Email-Based Identity Assertion**: prove control of
  the mailbox by clicking a magic link. In a real deployment the link is
  emailed; for the demo it is shown in the UI. Visiting it
  (`GET /ebia/verify?token=…`, single-use) proves mailbox control, mints a
  short-lived EBIA session, and redirects back to the Verifier frontend, which
  shows "email verified" and lets the user finish signing in with their wallet
  (see below). There are no dead ends — every email reaches at least this path.

The second page offers **"Continue with your identity wallet"** (if a browser
wallet extension is installed) in the cases where there is no pre-existing
provider binding — i.e. after a WebFinger **`trust`** result, or after mailbox
control is proven via **`ebia`**. (The **`oauth`** case is not offered the
wallet: the Verifier already has a Google binding, so it just uses the standard
redirect.) The wallet proves, with no redirect, that the user holds a PK Token
for their email; the backend verifies it at `/api/wallet/challenge` +
`/api/wallet/verify` using OpenPubkey's `VerifyPKToken` (OP signature, nonce
commitment, audience) and `VerifySignedMessage` (proof-of-possession over a
fresh challenge), then checks the token's email. In the `trust` case it also
requires the token's issuer to be the one the domain declared; in the `ebia`
case authority comes from mailbox control, so any issuer the verifier already
trusts is accepted. See `demo/extension`.

Components:

- `verifier/backend` — Go + Gin API. No database (demo accounts and provider
  bindings are hard-coded; OAuth state is kept in memory).
- `verifier/frontend` — Vue 3 + Vite single-page app, served by nginx in the
  container. nginx proxies `/api` to the backend.

### Run with Docker Compose

```sh
cd demo
docker compose up --build
```

Then open <http://localhost:5173>. The backend is also reachable directly at
<http://localhost:11110> (e.g. `GET /healthz`); it listens on 11110 because that
is one of the redirect ports registered for the Google OAuth client (see below).

### Run natively (without Docker)

Backend:

```sh
cd demo/verifier/backend
go run .            # listens on :11110
```

Frontend (in another terminal):

```sh
cd demo/verifier/frontend
npm install
npm run dev         # http://localhost:5173, proxies /api to :11110
```

### Google login

The `@gmail.com` path runs a standard OIDC authorization-code flow (with PKCE)
using **OpenPubkey's public Google OAuth client** (from
`providers/google.go` in <https://github.com/openpubkey/openpubkey>). Those
credentials are intentionally published by the OpenPubkey project, so the demo
can perform a real Google login without registering its own client.

Google enforces an **exact redirect-URI match** for that client, so the backend
must serve the callback at one of its registered loopback URIs —
`http://localhost:{3000,10001,11110}/login-callback`. The demo uses **11110**
(3000 collides with common dev servers). If you change the backend port, sign-in
with Google will fail with `redirect_uri_mismatch`; override the redirect with
the `GOOGLE_REDIRECT_URL` env var only if you point it at another registered
port.

Flow: **Continue with Google** → `GET /api/oauth/google/start` (redirects to
Google) → Google consent → `GET /login-callback` (backend exchanges the code and
verifies the ID token's signature, audience, issuer, and nonce) → redirect back
to the app, which shows the verified email. The backend needs outbound HTTPS to
Google at runtime; on a TLS-inspecting network see Troubleshooting.
