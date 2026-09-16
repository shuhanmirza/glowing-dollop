# Serves the abc.localhost demo namespace: a landing page and the
# /.well-known/byoid-configuration discovery document.
FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html /usr/share/nginx/html/index.html
# The well-known document is stored under well-known/ in the repo (dotfiles are
# awkward to track); place it at the dot-path nginx serves.
COPY well-known/byoid-configuration /usr/share/nginx/html/.well-known/byoid-configuration
EXPOSE 80
