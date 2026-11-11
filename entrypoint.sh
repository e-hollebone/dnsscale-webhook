#!/bin/sh
# DNSScale entrypoint — starts tailscaled (userspace) + dnsscale
set -e

TAILSCALE_SOCKET="/run/tailscale/tailscaled.sock"
TAILSCALE_STATE="/var/lib/tailscale/tailscaled.state"

# Retry budget for coming up. Overridable so an operator (or a test) can
# shorten a wait that is failing, without editing this script.
TS_WAIT_RETRIES="${TS_WAIT_RETRIES:-30}"
TS_WAIT_DELAY="${TS_WAIT_DELAY:-1}"

echo "dnsscale: starting tailscaled (userspace networking)..."

# Start tailscaled in userspace mode (no TUN/tap, no privileged mode)
tailscaled \
  --state="$TAILSCALE_STATE" \
  --socket="$TAILSCALE_SOCKET" \
  --userspace-networking &

# Wait for tailscaled socket
for _ in $(seq 1 "$TS_WAIT_RETRIES"); do
  if tailscale --socket="$TAILSCALE_SOCKET" status >/dev/null 2>&1; then
    break
  fi
  sleep "$TS_WAIT_DELAY"
done

# Authenticate if auth key provided and not already authenticated
if [ -n "$TS_AUTHKEY" ]; then
  if ! tailscale --socket="$TAILSCALE_SOCKET" status 2>/dev/null | grep -q "Tailscale is logged in"; then
    echo "dnsscale: authenticating to tailnet..."
    tailscale --socket="$TAILSCALE_SOCKET" up \
      --authkey="$TS_AUTHKEY" \
      --hostname="${TS_HOSTNAME:-dnsscale}" \
      --accept-routes
  else
    echo "dnsscale: already authenticated to tailnet"
  fi
fi

# Wait for a Tailscale IP
echo "dnsscale: waiting for Tailscale IP..."
for _ in $(seq 1 "$TS_WAIT_RETRIES"); do
  TS_IP=$(tailscale --socket="$TAILSCALE_SOCKET" ip -4 2>/dev/null | head -1)
  if [ -n "$TS_IP" ]; then
    echo "dnsscale: Tailscale IP = $TS_IP"
    break
  fi
  sleep "$TS_WAIT_DELAY"
done

if [ -z "$TS_IP" ]; then
  echo "dnsscale: ERROR — failed to acquire Tailscale IP"
  exit 1
fi

# --- TLS certificates -------------------------------------------------------
# api.tls_mode selects how the API is served:
#   off       - plain HTTP, no certificate
#   provided  - HTTPS using the certificate at API_TLS_CERT / API_TLS_KEY
#   tailscale - HTTPS using a certificate requested from the tailnet
# The webhook receiver requires HTTPS on port 80 or 443.
API_TLS_MODE="${API_TLS_MODE:-off}"

case "$API_TLS_MODE" in
  off)
    echo "dnsscale: TLS off — serving plain HTTP"
    ;;
  provided)
    if [ -z "$API_TLS_CERT" ] || [ -z "$API_TLS_KEY" ]; then
      echo "dnsscale: ERROR — API_TLS_MODE=provided requires API_TLS_CERT and API_TLS_KEY."
      exit 1
    fi
    if [ ! -f "$API_TLS_CERT" ] || [ ! -f "$API_TLS_KEY" ]; then
      echo "dnsscale: ERROR — certificate not found: $API_TLS_CERT / $API_TLS_KEY"
      exit 1
    fi
    echo "dnsscale: TLS provided (cert=$API_TLS_CERT key=$API_TLS_KEY)"
    ;;
  tailscale)
    API_TLS_CERT="${API_TLS_CERT:-/var/lib/tailscale/certs/cert.pem}"
    API_TLS_KEY="${API_TLS_KEY:-/var/lib/tailscale/certs/key.pem}"
    # `tailscale cert` takes the domain as a positional argument. It must be
    # this node's tailnet DNS name; Self.DNSName carries it (trailing dot
    # stripped). API_TLS_DOMAIN overrides the derivation.
    if [ -n "${API_TLS_DOMAIN:-}" ]; then
      TS_DOMAIN="$API_TLS_DOMAIN"
    else
      TS_DOMAIN=$(tailscale --socket="$TAILSCALE_SOCKET" status --json 2>/dev/null \
        | grep -oE '"DNSName": *"[^"]*"' | head -n1 \
        | sed -E 's/^"DNSName": *"//; s/"$//; s/\.$//')
    fi
    if [ -z "$TS_DOMAIN" ]; then
      echo "dnsscale: ERROR — could not determine the tailnet DNS name to request a certificate for."
      echo "dnsscale: set API_TLS_DOMAIN explicitly, or use API_TLS_MODE=provided."
      exit 1
    fi
    if [ ! -f "$API_TLS_CERT" ] || [ ! -f "$API_TLS_KEY" ]; then
      echo "dnsscale: requesting a Tailscale certificate for $TS_DOMAIN..."
      mkdir -p "$(dirname "$API_TLS_CERT")"
      if ! tailscale --socket="$TAILSCALE_SOCKET" cert \
           --cert-file="$API_TLS_CERT" --key-file="$API_TLS_KEY" "$TS_DOMAIN"; then
        echo "dnsscale: ERROR — could not obtain a Tailscale certificate."
        echo "dnsscale: mount a certificate instead (API_TLS_MODE=provided),"
        echo "dnsscale: or set API_TLS_MODE=off to serve plain HTTP."
        exit 1
      fi
    fi
    echo "dnsscale: TLS from tailnet (domain=$TS_DOMAIN cert=$API_TLS_CERT key=$API_TLS_KEY)"
    ;;
  *)
    echo "dnsscale: ERROR — invalid API_TLS_MODE '$API_TLS_MODE' (supported: off, provided, tailscale)"
    exit 1
    ;;
esac

export API_TLS_MODE API_TLS_CERT API_TLS_KEY

# `tailscale cert` needs operator rights, which on a stock node means root, so
# the entrypoint runs as root and drops to the unprivileged user for the
# application process only. Make the fetched certificate readable first.
if [ "$(id -u)" = "0" ] && [ -f "$API_TLS_CERT" ]; then
  chown dnsscale "$API_TLS_CERT" "$API_TLS_KEY" 2>/dev/null || true
fi

echo "dnsscale: starting dnsscale..."
if [ "$(id -u)" = "0" ]; then
  exec su-exec dnsscale dnsscale --config /etc/dnsscale/dnsscale.yaml
fi
exec dnsscale --config /etc/dnsscale/dnsscale.yaml