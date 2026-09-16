# BYOID PK Token Wallet (browser extension)

A Chrome (Manifest V3) extension that acts as an **OpenPubkey client in the
browser**: it runs a real OpenID Connect login against an OpenID Provider and
mints a **PK Token**, which it holds in a small wallet. This is the
trusted-local-agent idea (opkssh-style) relocated into the browser.

Click **Add Identity**, pick a provider (**Microsoft** or **Google**), sign in,
and see the identity listed by email and issuer with a valid/expired badge. Each
entry has **Details** (a read-only page showing every ID token claim and the PK
Token structure), **Refresh** (re-authenticate), and **Remove**.

The wallet can also **sign in to a verifier** with proof-of-possession, with no
redirect: a verifier page discovers the wallet, the wallet signs the verifier's
challenge with the key committed in its PK Token, and the verifier checks both
the PK Token and the signature. See "Signing in to a verifier" below.

## How it works

The PK Token crypto is **reused from OpenPubkey**, compiled to WebAssembly — we
do not reimplement it in JavaScript. The Go shim (`wasm/main.go`) exposes three
functions:

- `pktGenCommitment()` → generates an ephemeral key pair and the Client Instance
  Claims (CIC); returns the **nonce** (CIC hash) to place in the OIDC request.
  This commits the ephemeral public key inside the ID token the OP signs.
- `pktAssemble(sid, idToken)` → signs the CIC over the OP-signed ID token and
  returns the serialized **PK Token** together with the ephemeral **private key**
  (JWK), which the wallet persists so it can later prove possession.
- `pktSignChallenge(privateJwk, pkt, challenge)` → signs a verifier's challenge
  with the key committed in the PK Token, producing the proof-of-possession used
  when signing in to a verifier (see below).

JavaScript drives the OIDC flow around that:

1. The popup's **Add Identity** shows a provider picker; choosing one opens
   `add.html?op=<provider>` in a tab (it must persist across the login, so it is
   a tab, not the popup or the service worker).
2. `add.html` loads the WASM module and calls `pktGenCommitment()`.
3. It opens the chosen provider's sign-in page (authorization-code flow with
   PKCE).
4. The provider redirects to a loopback URI that nothing serves
   (`http://localhost:10001/login-callback`). The background service worker
   intercepts that navigation, reads the authorization code, closes the tab,
   and relays the code back.
5. `add.html` exchanges the code for an ID token and calls `pktAssemble(...)`.
6. The PK Token is stored in the wallet (`chrome.storage.local`), keyed by
   (provider, email) so the same email at two different OPs is kept as two
   distinct credentials.

### Reused OpenPubkey clients

We reuse OpenPubkey's **public clients** (from `providers/*.go` in
[openpubkey/openpubkey](https://github.com/openpubkey/openpubkey)) so the demo
can perform real logins without registering our own apps. They are public
clients using PKCE (Google requires a client secret even for its public app;
OpenPubkey intentionally publishes it, so it holds no power). The provider
registry lives in `src/config.js` — adding another OpenPubkey OP is a config
entry there (plus its token host in `rules.json` and `host_permissions`).

- **Microsoft (Azure)** — default tenant is Microsoft's "consumers" tenant, so
  **sign in with a personal Microsoft account** (outlook.com / live.com /
  hotmail.com).
- **Google** — sign in with a Google account.

Expect an "unverified app" consent screen for either — that is expected for a
shared demo client.

All OpenPubkey clients share loopback redirect URIs on ports 3000, 10001, and
11110. We use **10001** so the extension never collides with the Verifier demo
backend (which serves its own `/login-callback` on 11110).

#### Origin header stripping (AADSTS90023)

OpenPubkey's clients are *native/public* clients. When the extension exchanges
the authorization code for a token with `fetch()`, the browser adds an
`Origin: chrome-extension://<id>` header, and Microsoft rejects cross-origin
token redemption for non-SPA clients:

> AADSTS90023: Cross-origin token redemption is permitted only for the
> 'Single-Page Application' client-type …

To fix this without registering our own app or routing the token through a
server (which would defeat the point of a local wallet), a
`declarativeNetRequest` rule (`rules.json`) **strips the `Origin` header** from
the token-endpoint requests (one rule per OP token host). The OP then treats it
as a native redemption — exactly what OpenPubkey's own server-side exchange
does — and our `host_permissions` for the OP token hosts let us read the
response regardless of CORS.

## Build

The WASM module is a build artifact and is not checked in. Build it with Go
1.25+:

```sh
cd demo/extension/wasm
./build.sh          # writes ../pkt.wasm and ../wasm_exec.js
```

## Load the extension

1. Build the WASM module (above).
2. Open `chrome://extensions`, enable **Developer mode**.
3. **Load unpacked** → select `demo/extension`.
4. Click the extension icon → **Add Identity** → pick **Microsoft** or
   **Google** → sign in. The identity appears in the wallet with a **Valid**
   badge and the provider it came from.

## Layout

```
extension/
  manifest.json      MV3 manifest (WASM CSP, permissions, DNR ruleset, content script)
  rules.json         declarativeNetRequest rule: strip Origin on token requests
  background.js      service worker: intercept the loopback redirect; route wallet auth
  content.js         injected on verifier pages: byoid-* announce/authenticate bridge
  popup.html/.js     wallet view: list, details, refresh, remove, add (provider dropdown)
  add.html/.js       add-identity flow + WASM host (confetti on success)
  auth.html/.js      verifier sign-in consent page: pick token, approve, sign challenge
  details.html/.js   read-only page: all claims + PK Token structure
  styles.css         shared styles (dark "local wallet" theme)
  src/
    config.js        provider registry (reused OpenPubkey clients)
    oidc.js          PKCE, discovery, authorize URL, token exchange
    wallet.js        chrome.storage.local wallet (keyed by provider+email)
    pkt.js           decode a stored PK Token for display
    picker.js        shared "Add identity" provider dropdown
    confetti.js      self-contained success animation
  wasm/
    main.go          Go -> WASM OpenPubkey client shim
    build.sh         build script
    go.mod           pins openpubkey v0.26.0
    pop_test.mjs     Node test: proof-of-possession path
    verify_test.mjs  Node test: commitment + assemble path
```

## Signing in to a verifier (proof-of-possession)

The wallet presents a PK Token to a verifier and proves it holds the committed
key, without any redirect:

1. The verifier page asks installed wallets to announce themselves. The content
   script (`content.js`) injected on the verifier's origin replies over
   `window.postMessage` with our namespaced messages (an EIP-6963-style
   handshake, but with `byoid-*` messages so it never collides with crypto
   wallets). The private key never enters the verifier page.
2. The verifier fetches a fresh challenge and asks the chosen wallet to
   authenticate an email. The background worker opens a consent page
   (`auth.html`), which finds the matching PK Token, asks the user to approve,
   and signs the challenge with the committed key via the WASM
   `pktSignChallenge` (an OpenPubkey signed message).
3. The verifier posts the PK Token + signed challenge to its backend, which runs
   OpenPubkey's `VerifyPKToken` (OP signature, nonce commitment, audience) and
   `VerifySignedMessage` (proof-of-possession), and checks the token's email and
   issuer. See `demo/verifier`.

The ephemeral **private key is persisted** (in `chrome.storage.local`) so it can
sign challenges after the login. Hardening it to a non-extractable WebCrypto key
is a follow-up.

## Not in this milestone

- Hardening the stored private key to a non-extractable WebCrypto key.
- GQ signatures and the discovery/allowlist controls.
