# DNSScale with Webhook — build and test
#
# The test suite is self-contained. Unit, provider-contract, entrypoint-shell
# and end-to-end tests all run without external credentials; the end-to-end
# suite builds the real binary and points it at local fakes.
#
#   make build        compile the binary to bin/dnsscale
#   make test         unit + provider + entrypoint + end-to-end
#   make test-race    the same, under the race detector
#   make coverage     per-package statement coverage
#   make lint         go vet (both tag sets), gofmt, shellcheck
#   make test-live    real Tailscale certificate + real external APIs (opt-in)

GO ?= go
GOFLAGS ?=

.PHONY: all build test test-verbose test-race coverage lint test-live clean

all: build

build:
	$(GO) $(GOFLAGS) build -o bin/dnsscale .

test:
	$(GO) $(GOFLAGS) test ./...

test-verbose:
	$(GO) $(GOFLAGS) test -v ./...

test-race:
	$(GO) $(GOFLAGS) test -race ./...

coverage:
	$(GO) $(GOFLAGS) test -cover ./...
	$(GO) $(GOFLAGS) test -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1

# Live integration tests hit the real Tailscale and Cloudflare APIs. They are
# opt-in and need credentials in the environment; see live_test.go for the
# full list.
test-live:
	$(GO) $(GOFLAGS) test -tags live -v -run Live .

lint:
	$(GO) vet ./...
	$(GO) vet -tags live ./...
	@unclean="$$($(GO) fmt ./...)"; \
	if [ -n "$$unclean" ]; then \
	  echo "gofmt: these files need formatting:"; echo "$$unclean"; exit 1; \
	fi; \
	echo "gofmt: clean"
	sh -n entrypoint.sh
	@command -v shellcheck >/dev/null 2>&1 && shellcheck entrypoint.sh || \
	  echo "shellcheck not installed; skipped"

clean:
	rm -rf bin coverage.out
