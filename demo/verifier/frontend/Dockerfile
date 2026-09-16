# Build the Vue app, then serve the static output with nginx.
FROM node:22-alpine AS build
WORKDIR /app

# Trust extra CA certificates if provided (e.g. a corporate TLS-inspection
# root CA). Drop PEM (.crt) files into ./certs; this is a no-op when empty and
# lets `npm ci` work on networks that re-sign TLS with a private CA.
COPY certs/ /tmp/extra-certs/
RUN touch /usr/local/share/extra-ca.crt \
 && cat /tmp/extra-certs/*.crt >> /usr/local/share/extra-ca.crt 2>/dev/null || true
ENV NODE_EXTRA_CA_CERTS=/usr/local/share/extra-ca.crt

COPY package.json package-lock.json ./
RUN npm ci

COPY . .
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
