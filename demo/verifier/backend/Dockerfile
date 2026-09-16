# Build the Verifier backend as a small static binary, then run it on Alpine.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Trust extra CA certificates if provided (e.g. a corporate TLS-inspection
# root CA). Drop PEM (.crt) files into ./certs; this is a no-op when empty and
# lets `go mod download` work on networks that re-sign TLS with a private CA.
COPY certs/ /tmp/extra-certs/
RUN touch /usr/local/share/ca-bundle.crt \
 && cat /etc/ssl/certs/ca-certificates.crt >> /usr/local/share/ca-bundle.crt 2>/dev/null || true; \
    cat /tmp/extra-certs/*.crt >> /usr/local/share/ca-bundle.crt 2>/dev/null || true
ENV SSL_CERT_FILE=/usr/local/share/ca-bundle.crt

# Cache dependencies first for faster rebuilds.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/verifier-backend .

FROM alpine:3.20
# The backend makes outbound HTTPS calls at runtime (Google's OIDC discovery,
# JWKS, and token endpoints), which need a CA bundle. Rather than `apk add
# ca-certificates` (a network fetch that itself fails on TLS-inspecting
# networks, since this fresh image does not yet trust the corporate CA), copy
# the bundle the build stage already assembled. That bundle contains the base
# CAs plus any corporate TLS-inspection CA from ./certs, so runtime HTTPS works
# on both normal and inspecting networks with no network access here.
COPY --from=build /usr/local/share/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
RUN adduser -D -u 10001 appuser
COPY --from=build /out/verifier-backend /usr/local/bin/verifier-backend
USER appuser
ENV PORT=11110
EXPOSE 11110
ENTRYPOINT ["/usr/local/bin/verifier-backend"]
