# Demo namespace domain (`abc.localhost`)

Stands in for a real organization's domain (e.g. `owasp.org`) in the
blind-relay demo. It does two things:

1. Serves a **landing page** (`index.html`) with its own distinct look, so it is
   visually obvious this is a *different party* from the Verifier (`xyz.com`) and
   the relay.
2. Publishes the **BYOID configuration** the Verifier fetches to learn how to
   authenticate the domain's users:

   ```
   GET http://abc.localhost/.well-known/byoid-configuration
   ```

   ```json
   {
     "byoid_version": "0.1",
     "namespace": "abc.localhost",
     "issuer": "http://op.localhost:5556",
     "client_id": "byoid-relay-client",
     "relay_redirect_uri": "http://relayoidc.localhost:9090/cb",
     "scopes": "openid email profile",
     "binding_mode": "split-pkce"
   }
   ```

The domain owner has adopted nothing beyond publishing this static file: it
declares that its users' issuer is the demo OP and delegates a **blind relay**
to front the OAuth flow. **Serving this document under the domain (over TLS in
production) is the authorization root** — the Verifier trusts it because it came
from `abc.localhost` itself.

The demo user `alice@abc.localhost` lives in the OP (see `demo/op`).

## Run

Served by nginx via docker-compose (from `demo/`):

```sh
docker compose up abc        # or: docker compose up
```

- Landing page: <http://abc.localhost:8081/>
- Config: <http://abc.localhost:8081/.well-known/byoid-configuration>

Inside the compose network the Verifier reaches it as `http://abc.localhost/`
(port 80) via a network alias; the `8081` mapping is for viewing from the host.
Chrome resolves `*.localhost` to loopback automatically; other tools may need an
`/etc/hosts` entry (see `demo/op/README.md`).

## Files

```
abc/
  index.html                        landing page (distinct UI)
  nginx.conf                        serves the page + the well-known JSON
  well-known/byoid-configuration    the BYOID discovery document
  Dockerfile                        nginx image with the above baked in
```
