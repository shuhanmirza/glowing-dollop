# Blind relay (`relayoidc.localhost`)

The **untrusted, multi-tenant blind relay**. A namespace
domain (`abc.localhost`) delegates to it so a Verifier that has no relationship
with the domain's OP can still authenticate the domain's users — without the
relay ever being able to see the token or forge a user.

## What it does (and does not do)

The relay owns the OAuth **redirect URI registered at the OP**
(`http://relayoidc.localhost:9090/cb`), which a stranger Verifier cannot
register itself. When the OP redirects the browser back with `?code&state`, the
relay:

1. verifies `state` — a **signed JWT** (compact ES256 JWS, `typ:
   byoid-routing+jwt`) the Verifier issued. The relay fetches the public key
   from the **callback's own domain** (`<callback-origin>/.well-known/byoid-verifier`)
   and checks the signature, audience, and expiry (see below);
2. shows a **consent page** (see `consent.go`) naming the Verifier that will
   receive the code, the OP that authenticated the user, and the scopes the
   Verifier will obtain;
3. on approval, relays the browser to the callback carried in the state,
   passing `code` / `state` through; on cancel, relays `error=access_denied`.

That is the **whole** job. The relay:

- **never redeems the code** — it holds no `code_verifier` (split-PKCE: the
  Verifier generated the verifier and kept it), so it **cannot** exchange the
  code for a token. It is cryptographically **blind**.
- **never mints anything** — it has no signing key and issues no tokens.

Worst case, a malicious relay can misroute or drop the code (a liveness/DoS
issue) or learn `(domain, verifier)` routing metadata — but the code is useless
without the Verifier's `code_verifier`, so it cannot obtain a token.

## Routing authentication (signed state)

The routing instruction is a **signed request** (RFC 9101 / JAR-style, adapted
so the *relay* — not an OP — is the verifier). The Verifier signs a compact
ES256 JWS over `{ aud, cb, sid, op, scope, step, jti, iat, exp }` and publishes
its public key at `GET <verifier-origin>/.well-known/byoid-verifier` (a JWKS).

**The key is located from the callback, not from a claim.** The relay derives
the JWKS URL from the `cb` origin (`<cb-origin>/.well-known/byoid-verifier`), so
the domain that will *receive* the code is, by construction, the same domain
whose key must have *signed* the request. There is no separate `iss` claim to
point the key lookup elsewhere — this is what closes the open-redirector hole (a
signer can only ever route the code back to its own domain; the relayed code is
still useless to that domain without its `code_verifier`).

On each callback the relay (`verify.go`), in this order:

1. **pre-checks the unverified claims before any network/crypto** — `typ`,
   `aud == ` this relay's origin, `exp`/`iat` freshness, and a usable `cb` URL.
   A junk or misaddressed request is dropped here, before any JWKS fetch, so an
   unauthenticated caller cannot make the relay do outbound work cheaply;
2. **fetches the JWKS from the callback origin** and verifies the **signature**
   (`kid`), then re-checks `aud`/`exp` on the *verified* payload;
3. enforces a **single-use `jti`** (consumed at `/relay`, so a captured link
   cannot be replayed).

**SSRF hardening of the JWKS fetch** — the callback is attacker-settable until
the signature is checked, so the fetch is guarded:

- **no IP-literal hosts** and **public IPs only**: the host is resolved and
  rejected if it maps to a loopback/private/link-local address;
- **resolve once, pin the dial** to that IP, so a DNS rebind between the check
  and the connection cannot redirect the fetch to an internal address;
- **no HTTP redirects** (a `3xx` could otherwise bounce the fetch to an internal
  host);
- **bounded key cache** (keyed by callback origin) so a flood of distinct hosts
  cannot grow memory without limit;
- an explicit **demo carve-out** (`VERIFIER_ALLOWED_HOSTS`, default
  `xyz.localhost,localhost,127.0.0.1`) lets the local `*.localhost` verifier —
  which intentionally resolves to loopback — be reached; production origins do
  not need it.

`RELAY_ORIGIN` sets the expected `aud` (default
`http://relayoidc.localhost:9090`).

**Cannot verify the code originated at the OP.** The callback is a browser
redirect, and the relay is blind (no `code_verifier`), so it cannot prove the
`code` was really issued by the OP. It does not need to: code authenticity is
enforced by **PKCE at the Verifier's redemption** — a forged or injected code
fails the exchange. (JARM would give OP-signed response authenticity, but it
requires OP support, which conflicts with the unmodified-OP premise.)

### Hardening for a real (internet-facing) deployment

This is a demo. A production multi-tenant relay should additionally: rate-limit
`/cb` and `/relay` (the pre-check bounds work per request, but an infra-layer
limit bounds volume); consider serving a static consent shell on `/cb` and
deferring even the JWKS fetch to the human-driven `POST /relay`; and cache JWKS
with sane TTLs honoring `Cache-Control`.

**What the signature does and does not prove.** A valid signature proves the
routing state came from the origin at `iss`, and the `cb`-origin==`iss`-origin
check proves *"the code goes to that Verifier"* — those are cryptographically
grounded. The `op` and `scope` values shown on the consent page, however, are
read from the Verifier's signed state: they are authenticated as the Verifier's
*own statement*, not independently verified. The relay is blind — it never sees
the OP exchange — so it cannot confirm the user actually authenticated at that
OP or that those are the exact granted scopes.

## Run

```sh
docker compose up relay        # from demo/  (or: docker compose up)
```

- Landing page (distinct UI): <http://relayoidc.localhost:9090/>
- Callback (used by the OP → Verifier relay): `/cb`
- Health: `/healthz`

`PORT` overrides the listen port (default `9090`). Chrome resolves
`*.localhost` to loopback automatically; other tools may need an `/etc/hosts`
entry (see `demo/op/README.md`).

## Where it sits in the flow

```
Verifier → OP authorize (redirect_uri = relay/cb, state = signed JWT, PKCE challenge)
OP → browser → relay/cb?code&state
relay: verify signed state (sig via <cb-origin>/.well-known/byoid-verifier, aud, exp, jti)
relay → browser: consent page (which Verifier, which OP, which scopes)
   ├─ Cancel  → Verifier cb?error=access_denied
   └─ Continue → POST /relay → consume jti → Verifier cb?code&state   ← relay (blind)
Verifier → OP token (code + code_verifier, no secret) → ID token       ← Verifier redeems
```

## Endpoints

- `/cb` — OP redirect target; verifies the signed state and renders consent.
- `/relay` — consent form target; re-verifies, consumes the single-use `jti`,
  then relays (or denies).
- `/` — landing page (distinct UI).
- `/healthz` — health check.
