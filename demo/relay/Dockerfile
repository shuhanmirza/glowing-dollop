# Build the blind relay as a small static binary, then run it on Alpine.
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
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o /out/relay .

FROM alpine:3.20
# The relay makes outbound HTTPS calls at runtime (fetching the Verifier's
# JWKS for routing-state verification). Copy the CA bundle the build stage
# assembled (base CAs plus any corporate TLS-inspection CA from ./certs)
# rather than `apk add ca-certificates`, which would itself fail on a
# TLS-inspecting network from this fresh image.
COPY --from=build /usr/local/share/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
RUN adduser -D -u 10001 appuser
COPY --from=build /out/relay /usr/local/bin/relay
USER appuser
ENV PORT=9090
EXPOSE 9090
ENTRYPOINT ["/usr/local/bin/relay"]
