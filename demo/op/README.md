# Demo OpenID Provider (`op.localhost`)

A minimal, **unmodified** OpenID Connect provider — [Dex](https://dexidp.io) —
used to demonstrate that the BYOID wallet mints PK tokens against a real OP the
project does not control. It hosts one public PKCE client and one demo user.

- **Issuer:** `http://op.localhost:5556`
- **Client:** `byoid-demo` (public, PKCE, no secret)
- **Redirect URI:** `http://localhost:10001/login-callback` (the extension
  intercepts this loopback URL to capture the auth code)
- **User:** `alice@abc.localhost` / `password123`

Everything is declared in [`config.yaml`](./config.yaml); state is in-memory and
reseeded from that file on every start, so the demo is fully reproducible.

## Run it

From `demo/`:

```sh
docker compose up op        # or: docker compose up   (starts the whole demo)
```

Dex listens on `:5556`. Verify it is up:

```sh
curl http://localhost:5556/.well-known/openid-configuration
```

## Why `op.localhost` (and hostname setup)

The extension calls the OP from an extension page, which is a **secure
context**. Chrome blocks cleartext `http://` requests to non-localhost hosts
from there. Two properties of the `*.localhost` domain make this work with no
extra setup **in Chrome**:

1. Chrome resolves any `*.localhost` name (e.g. `op.localhost`) to the loopback
   address automatically — no DNS or `/etc/hosts` entry needed.
2. Chrome treats `*.localhost` as a **secure context**, so the extension may
   call it over plain `http` without certificates.

So for the Chrome-based demo, **`docker compose up` is all you need** — no host
file edits, no TLS.

### Other tools / browsers

Non-Chrome tooling (curl, Go, Firefox, some OS resolvers) may **not** resolve
`*.localhost` automatically. If you need to reach `op.localhost` from such a
tool, add a hosts entry:

```
# /etc/hosts   (Linux/macOS)   —   C:\Windows\System32\drivers\etc\hosts (Windows)
127.0.0.1   op.localhost
```

Or just use `http://localhost:5556` / `http://127.0.0.1:5556` directly (the
discovery document always advertises the canonical `http://op.localhost:5556`
issuer regardless of how you connect).

## Use it from the wallet extension

1. Start the OP (above) and load the extension (see `demo/extension/README.md`).
2. Click **Add Identity** → **Demo OP (abc.localhost)**.
3. Sign in as `alice@abc.localhost` / `password123`.
4. A PK token for `alice@abc.localhost` (issuer `http://op.localhost:5556`) appears in
   the wallet.

## Notes

- **Public client, no secret:** the wallet redeems the code with PKCE and no
  `client_secret`, matching the extension's public-client model. Unlike
  Microsoft/Google, Dex does not gate token redemption on the `Origin` header,
  so no `declarativeNetRequest` Origin-strip rule is needed for this OP.
- **Namespace:** the single user lives at `abc.localhost`, the demo namespace used
  throughout the project. Add more users under `staticPasswords` in
  `config.yaml` (generate a bcrypt hash, e.g. `htpasswd -bnBC 10 "" password | tr -d ':\n'`).
