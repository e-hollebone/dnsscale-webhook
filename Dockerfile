# ---- build stage ----
FROM golang:1.24.7-alpine AS build

RUN apk add --no-cache git make

WORKDIR /src

# Copy go modules first for better layer caching
COPY go.mod go.sum .

# Download dependencies
RUN go mod download

# Copy the source
COPY . ./

# Build dnsscale binary
RUN CGO_ENABLED=0 go build -o /dnsscale .

# ---- runtime stage ----
FROM alpine:3.20

# Install tailscale (official package for userspace networking)
RUN apk add --no-cache \
    tailscale \
    ca-certificates \
    tini \
    && rm -rf /var/cache/apk/*

# Create dnsscale user
RUN adduser -D -u 10001 dnsscale

# Copy built binary
COPY --from=build /dnsscale /usr/local/bin/dnsscale

# Install su-exec for dropping privileges
RUN apk add --no-cache su-exec

# Copy entrypoint script
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# The entrypoint deliberately runs as root: `tailscale cert` needs operator
# rights, and on a stock node only root has them. It drops to the unprivileged
# `dnsscale` user with su-exec before starting the application, so the daemon
# never runs as root. The webhook listener is reachable on the tailnet only.
#
# Entrypoint starts tailscaled (userspace) + dnsscale
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["/usr/local/bin/entrypoint.sh"]
