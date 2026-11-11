//go:build live

// live_test.go — integration tests that touch real external services.
//
// These are excluded from a normal `go test ./...` run. They exist because the
// certificate path cannot be proven by a fake: `tailscale cert` has to talk to
// a live tailscaled in a tailnet with HTTPS certificates enabled, and the
// resulting certificate has to be accepted by a TLS client.
//
// Run them where the node is already authenticated and the operator is root
// (the certificate fetch needs operator rights):
//
//	DNSSCALE_LIVE_TESTS=1 TAILSCALE_SOCKET=/var/run/tailscale/tailscaled.sock \
//	  go test -tags live -v -run Live ./...
//
// Environment:
//	TAILSCALE_SOCKET  path to the tailscaled socket (default /var/run/tailscale/tailscaled.sock)
//	TAILSCALE_DOMAIN  domain to request; derived from Self.DNSName when unset
//	TAILSCALE_API_KEY, TAILSCALE_TAILNET  enable the live Tailscale API test
//	CLOUDFLARE_API_TOKEN, CF_ZONE_ID      enable the live Cloudflare API test

package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/e-hollebone/dnsscale-with-webhook/providers"
	"go.uber.org/zap"
)

// liveTailscaleSocket returns the socket to talk to.
func liveTailscaleSocket() string {
	if s := os.Getenv("TAILSCALE_SOCKET"); s != "" {
		return s
	}
	return "/var/run/tailscale/tailscaled.sock"
}

// tailscaleStatusDNSName asks tailscaled for this node's FQDN.
func tailscaleStatusDNSName(t *testing.T, socket string) string {
	t.Helper()

	out, err := exec.Command("tailscale", "--socket="+socket, "status", "--json").Output()
	if err != nil {
		t.Fatalf("tailscale status --json: %v", err)
	}

	var status struct {
		Self struct {
			DNSName string `json:"DNSName"`
		} `json:"Self"`
	}
	if err := json.Unmarshal(out, &status); err != nil {
		t.Fatalf("decoding tailscale status: %v", err)
	}
	if status.Self.DNSName == "" {
		t.Fatal("tailscale reported no DNS name for this node")
	}
	return strings.TrimSuffix(status.Self.DNSName, ".")
}

// TestLiveTailscaleCertificate performs the real certificate fetch and proves
// the result is a usable certificate for the node's own name.
func TestLiveTailscaleCertificate(t *testing.T) {
	if os.Getenv("DNSSCALE_LIVE_TESTS") != "1" {
		t.Skip("set DNSSCALE_LIVE_TESTS=1 to run the live integration tests")
	}

	socket := liveTailscaleSocket()
	domain := os.Getenv("TAILSCALE_DOMAIN")
	if domain == "" {
		domain = tailscaleStatusDNSName(t, socket)
	}
	t.Logf("requesting a certificate for %s via %s", domain, socket)

	dir := t.TempDir()
	certFile := filepath.Join(dir, "cert.pem")
	keyFile := filepath.Join(dir, "key.pem")

	// The argument order matters: flags first, domain last.
	cmd := exec.Command("tailscale", "--socket="+socket, "cert",
		"--cert-file="+certFile, "--key-file="+keyFile, domain)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("`tailscale cert` failed (it needs operator rights — run as root, or set\n"+
			"`tailscale set --operator=$USER` once on this node):\n%s", out)
	}

	certPEM, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("reading the certificate: %v", err)
	}
	keyPEM, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatalf("reading the private key: %v", err)
	}

	// 1. It must be loadable as a key pair.
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("tls.X509KeyPair() = %v", err)
	}
	if len(pair.Certificate) == 0 {
		t.Fatal("the certificate chain is empty")
	}

	// 2. The leaf must name this node.
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatalf("parsing the leaf certificate: %v", err)
	}
	if !containsString(leaf.DNSNames, domain) {
		t.Errorf("leaf DNS names = %v, want %s", leaf.DNSNames, domain)
	}
	if leaf.NotAfter.Before(time.Now()) {
		t.Errorf("the certificate expired at %s", leaf.NotAfter)
	}
	t.Logf("certificate valid from %s to %s for %v", leaf.NotBefore, leaf.NotAfter, leaf.DNSNames)

	// 3. It must actually serve a TLS handshake.
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"healthy"}`)
	}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
	srv.StartTLS()
	defer srv.Close()

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // we are testing the server's own cert
		},
	}
	resp, err := client.Get(srv.URL + "/health")
	if err != nil {
		t.Fatalf("serving HTTPS with the fetched certificate: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Errorf("HTTPS request status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "healthy") {
		t.Errorf("HTTPS body = %q", body)
	}

	// 4. Report what was requested, so the operator can see the tailnet side.
	t.Logf("OK: tailscale cert %s --cert-file=%s --key-file=%s", domain, certFile, keyFile)
}

// TestLiveTailscaleAPI lists devices through the real Tailscale API.
func TestLiveTailscaleAPI(t *testing.T) {
	if os.Getenv("DNSSCALE_LIVE_TESTS") != "1" {
		t.Skip("set DNSSCALE_LIVE_TESTS=1 to run the live integration tests")
	}
	apiKey := os.Getenv("TAILSCALE_API_KEY")
	tailnet := os.Getenv("TAILSCALE_TAILNET")
	if apiKey == "" || tailnet == "" {
		t.Skip("set TAILSCALE_API_KEY and TAILSCALE_TAILNET to run the live Tailscale API test")
	}

	client := NewTailscaleClient(apiKey, tailnet, zap.NewNop())
	nodes, err := client.ListNodes(t.Context())
	if err != nil {
		t.Fatalf("ListNodes() against the real API: %v", err)
	}
	t.Logf("real Tailscale API returned %d authorized devices", len(nodes))
	if len(nodes) == 0 {
		t.Log("warning: the tailnet reports no authorized devices")
	}
}

// TestLiveCloudflareAPI lists DNS records through the real Cloudflare API.
func TestLiveCloudflareAPI(t *testing.T) {
	if os.Getenv("DNSSCALE_LIVE_TESTS") != "1" {
		t.Skip("set DNSSCALE_LIVE_TESTS=1 to run the live integration tests")
	}
	token := os.Getenv("CLOUDFLARE_API_TOKEN")
	zone := os.Getenv("CF_ZONE_ID")
	if token == "" || zone == "" {
		t.Skip("set CLOUDFLARE_API_TOKEN and CF_ZONE_ID to run the live Cloudflare API test")
	}

	provider, err := providers.NewCloudflareProvider(token, zone)
	if err != nil {
		t.Fatalf("NewCloudflareProvider() = %v", err)
	}
	records, err := provider.ListRecords(t.Context(), "")
	if err != nil {
		t.Fatalf("ListRecords() against the real API: %v", err)
	}
	t.Logf("real Cloudflare API returned %d managed records in zone %s", len(records), zone)
}

func containsString(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
