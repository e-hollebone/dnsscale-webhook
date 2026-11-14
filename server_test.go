package main

// server_test.go — verification for the self-describing API.
//
// The tests use an httptest server for the Tailscale API and a fake DNS provider,
// so no test touches the network. They cover the two consumer contracts (human
// HTML, agent JSON), the discovery standards (RFC 8631 Link headers, RFC 5785
// well-known), the health logic, credential redaction, the sync trigger and the
// Tailscale webhook signature verification.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/e-hollebone/dnsscale-webhook/providers"
	"go.uber.org/zap"
)

// fakeProvider is an in-memory providers.DNSProvider.
type fakeProvider struct {
	records []providers.DNSRecord
	err     error
}

func (f *fakeProvider) ListRecords(ctx context.Context, zone string) ([]providers.DNSRecord, error) {
	return f.records, f.err
}

func (f *fakeProvider) CreateRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	return nil
}

func (f *fakeProvider) UpdateRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	return nil
}

func (f *fakeProvider) DeleteRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	return nil
}

// newTestServer builds a Server backed by a fake Tailscale API and DNS provider.
func newTestServer(t *testing.T, tsResponse string, tsStatus int, provider providers.DNSProvider) (*Server, *DNSReconciler) {
	t.Helper()

	tsAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(tsStatus)
		w.Write([]byte(tsResponse))
	}))
	t.Cleanup(tsAPI.Close)

	tsClient := &TailscaleClient{
		apiKey:     "tskey-api-test",
		tailnet:    "example.ts.net",
		logger:     zap.NewNop(),
		httpClient: tsAPI.Client(),
		baseURL:    tsAPI.URL,
	}

	reconciler := NewDNSReconciler(tsClient, provider, "example.com", 30*time.Second, zap.NewNop())
	// Seed the cache so /api/v1/nodes has content.
	reconciler.nodeCache["n1"] = TailscaleNode{
		ID: "n1", Name: "web-server", Hostname: "web-server",
		Addresses: []string{"100.64.1.1"}, Online: true,
	}
	reconciler.recordSync()

	cfg := &Config{
		Tailscale: TailscaleConfig{APIKey: "tskey-api-abcdef123456", Tailnet: "example.ts.net"},
		DNS: DNSConfig{
			Provider: "cloudflare",
			Domain:   "example.com",
			ZoneID:   "zone-12345",
			Cloudflare: CloudflareConfig{
				APIToken: "cf-token-abcdef123456",
			},
		},
		App:     AppConfig{Workers: 2, PollInterval: 30 * time.Second},
		Logging: LoggingConfig{Level: "info", Format: "console"},
		API:     APIConfig{Enabled: true, BindAddr: ":8080"},
		Webhook: WebhookConfig{Enabled: true, Secret: "test-webhook-secret", Path: "/api/v1/webhook"},
	}

	srv := NewServer(ServerConfig{
		BindAddr:    ":8080",
		Webhook:     cfg.Webhook,
		Reconciler:  reconciler,
		Tailscale:   tsClient,
		DNSProvider: provider,
		Config:      cfg,
		Logger:      zap.NewNop(),
	})

	return srv, reconciler
}

const testDevicesResponse = `{
	"devices": [
		{
			"id": "n1",
			"name": "web-server.tail123.ts.net",
			"hostname": "web-server",
			"authorized": true,
			"addresses": ["100.64.1.1"],
			"lastSeen": "2026-11-10T12:00:00Z"
		}
	]
}`

// ---------------------------------------------------------------------------
// Human consumer
// ---------------------------------------------------------------------------

func TestServerHumanPage(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("GET / Content-Type = %q, want text/html", ct)
	}

	body := rr.Body.String()
	for _, want := range []string{
		"DNSScale",
		"/health",
		"/api/v1/endpoints",
		"/api/v1/sync",
		"Sync Now",
		"service-desc",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("GET / body missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// Agent consumer — discovery
// ---------------------------------------------------------------------------

func TestServerDiscoveryDocuments(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	tests := []struct {
		path         string
		wantStatus   int
		wantContains []string
	}{
		{"/api", http.StatusOK, []string{"dnsscale", "endpoints", "service-desc"}},
		{"/api/v1/endpoints", http.StatusOK, []string{"health", "sync", "webhook"}},
		{"/.well-known/dnsscale", http.StatusOK, []string{"dnsscale", "/api/v1/endpoints", "/health"}},
	}

	for _, tc := range tests {
		rr := httptest.NewRecorder()
		srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, tc.path, nil))

		if rr.Code != tc.wantStatus {
			t.Errorf("GET %s status = %d, want %d", tc.path, rr.Code, tc.wantStatus)
		}
		body := rr.Body.String()
		for _, want := range tc.wantContains {
			if !strings.Contains(body, want) {
				t.Errorf("GET %s body missing %q", tc.path, want)
			}
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &doc); err != nil {
			t.Errorf("GET %s is not valid JSON: %v", tc.path, err)
		}
	}
}

func TestServerLinkHeadersOnEveryResponse(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	for _, path := range []string{"/", "/health", "/api", "/api/v1/endpoints", "/.well-known/dnsscale", "/api/v1/status"} {
		rr := httptest.NewRecorder()
		srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))

		link := rr.Header().Get("Link")
		for _, rel := range []string{"service-doc", "service-desc", "status"} {
			if !strings.Contains(link, `rel="`+rel+`"`) {
				t.Errorf("GET %s Link header missing rel=%q: %s", path, rel, link)
			}
		}
		if rr.Header().Get("X-API-Service") != "dnsscale" {
			t.Errorf("GET %s X-API-Service = %q", path, rr.Header().Get("X-API-Service"))
		}
	}
}

func TestServerUnknownPathPointsAtDiscovery(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/nope", nil))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET /nope status = %d, want 404", rr.Code)
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("404 body is not JSON: %v", err)
	}
	next, ok := body["next_steps"].([]interface{})
	if !ok || len(next) == 0 {
		t.Fatalf("404 body missing next_steps: %v", body)
	}
	if !strings.Contains(rr.Body.String(), "/api/v1/endpoints") {
		t.Errorf("404 body does not point at /api/v1/endpoints: %s", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

func TestServerHealthHealthy(t *testing.T) {
	provider := &fakeProvider{records: []providers.DNSRecord{{Name: "a.example.com", Type: "A", Value: "100.64.1.1", TTL: 300}}}
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, provider)

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}

	var body struct {
		Status  string                 `json:"status"`
		Checks  map[string]interface{} `json:"checks"`
		Metrics map[string]interface{} `json:"metrics"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if body.Status != "healthy" {
		t.Errorf("status = %q, want healthy; checks=%v", body.Status, body.Checks)
	}
	if body.Checks["tailscale_api"] != "reachable" {
		t.Errorf("tailscale_api check = %v", body.Checks["tailscale_api"])
	}
	if body.Checks["dns_provider"] != "reachable" {
		t.Errorf("dns_provider check = %v", body.Checks["dns_provider"])
	}

	// Uptime Kuma matches the exact serialized keyword; a bare "healthy" would
	// also match "unhealthy" and could never fire.
	if !strings.Contains(rr.Body.String(), `"status":"healthy"`) {
		t.Errorf("body lacks the exact keyword \"status\":\"healthy\": %s", rr.Body.String())
	}
}

func TestServerHealthUnhealthyWhenDependencyFails(t *testing.T) {
	provider := &fakeProvider{err: context.DeadlineExceeded}
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, provider)

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("GET /health status = %d, want 503; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"status":"unhealthy"`) {
		t.Errorf("body does not report unhealthy: %s", rr.Body.String())
	}
}

func TestServerHealthDegradedWhenNoDevices(t *testing.T) {
	srv, _ := newTestServer(t, `{"devices":[]}`, http.StatusOK, &fakeProvider{})

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/health", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("GET /health status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), `"status":"degraded"`) {
		t.Errorf("body does not report degraded: %s", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// Config redaction
// ---------------------------------------------------------------------------

func TestServerConfigRedactsCredentials(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))

	body := rr.Body.String()
	for _, secret := range []string{"tskey-api-abcdef123456", "cf-token-abcdef123456", "test-webhook-secret"} {
		if strings.Contains(body, secret) {
			t.Errorf("config response leaked credential %q", secret)
		}
	}
	if !strings.Contains(body, `"api_key":"tske...3456"`) {
		t.Errorf("config response does not show a masked api_key: %s", body)
	}
	// Non-secret values stay readable.
	if !strings.Contains(body, "example.com") {
		t.Errorf("config response lost the domain: %s", body)
	}
}

// ---------------------------------------------------------------------------
// Sync trigger
// ---------------------------------------------------------------------------

func TestServerSyncTriggerQueuesSync(t *testing.T) {
	srv, reconciler := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	if len(reconciler.trigger) != 0 {
		t.Fatalf("trigger channel not empty at start")
	}

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/sync", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/sync status = %d, want 200", rr.Code)
	}
	if len(reconciler.trigger) != 1 {
		t.Errorf("trigger channel length = %d, want 1", len(reconciler.trigger))
	}

	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if triggered, ok := body["triggered"].(bool); !ok || !triggered {
		t.Errorf("triggered = %v, want true", body["triggered"])
	}
}

func TestServerSyncRejectsGet(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/sync", nil))

	if rr.Code != http.StatusNotFound {
		t.Errorf("GET /api/v1/sync status = %d, want 404", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Webhook signature verification
// ---------------------------------------------------------------------------

// sign builds a Tailscale-Webhook-Signature header value for the given body.
func sign(secret string, timestamp int64, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return "t=" + strconv.FormatInt(timestamp, 10) + ",v1=" + hex.EncodeToString(mac.Sum(nil))
}

func TestVerifyWebhookSignature(t *testing.T) {
	secret := "test-webhook-secret"
	body := []byte(`[{"timestamp":"2026-11-10T12:00:00Z","version":1,"type":"deviceCreated","tailnet":"example.ts.net","message":"node created"}]`)

	tests := []struct {
		name    string
		header  string
		wantErr bool
	}{
		{"valid", sign(secret, time.Now().Unix(), body), false},
		{"wrong secret", sign("other-secret", time.Now().Unix(), body), true},
		{"stale timestamp", sign(secret, time.Now().Add(-10*time.Minute).Unix(), body), true},
		{"missing header", "", true},
		{"missing v1", "t=" + strconv.FormatInt(time.Now().Unix(), 10), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook", strings.NewReader(string(body)))
			if tc.header != "" {
				req.Header.Set("Tailscale-Webhook-Signature", tc.header)
			}

			events, err := verifyWebhookSignature(req, body, secret)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got events=%v", events)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(events) != 1 || events[0].Type != "deviceCreated" {
				t.Errorf("events = %+v, want one deviceCreated", events)
			}
		})
	}
}

func TestServerWebhookAcceptedAndTriggersSync(t *testing.T) {
	srv, reconciler := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	body := []byte(`[{"timestamp":"2026-11-10T12:00:00Z","version":1,"type":"deviceDeleted","tailnet":"example.ts.net","message":"node deleted"}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook", strings.NewReader(string(body)))
	req.Header.Set("Tailscale-Webhook-Signature", sign("test-webhook-secret", time.Now().Unix(), body))

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/webhook status = %d, want 200; body=%s", rr.Code, rr.Body.String())
	}
	if len(reconciler.trigger) != 1 {
		t.Errorf("trigger channel length = %d, want 1", len(reconciler.trigger))
	}
}

func TestServerWebhookRejectsBadSignature(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	body := []byte(`[{"type":"deviceCreated"}]`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webhook", strings.NewReader(string(body)))
	req.Header.Set("Tailscale-Webhook-Signature", sign("wrong-secret", time.Now().Unix(), body))

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/v1/webhook status = %d, want 401", rr.Code)
	}
}

func TestServerWebhookDisabledReturns404(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})
	srv.cfg.Webhook.Enabled = false

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/v1/webhook", strings.NewReader("[]")))

	if rr.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// Helpers under test
// ---------------------------------------------------------------------------

func TestRedact(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"short", "***"},
		{"tskey-api-abcdef123456", "tske...3456"},
	}
	for _, tc := range tests {
		if got := redact(tc.in); got != tc.want {
			t.Errorf("redact(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestHumanDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{0, "0m"},
		{90 * time.Second, "1m"},
		{2*time.Hour + 14*time.Minute, "2h 14m"},
		{3*24*time.Hour + 2*time.Hour, "3d 2h"},
	}
	for _, tc := range tests {
		if got := humanDuration(tc.d); got != tc.want {
			t.Errorf("humanDuration(%v) = %q, want %q", tc.d, got, tc.want)
		}
	}
}

func TestTriggerSyncNeverBlocks(t *testing.T) {
	_, reconciler := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 100; i++ {
			reconciler.TriggerSync()
		}
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("TriggerSync blocked after the buffered trigger was full")
	}

	if len(reconciler.trigger) != 1 {
		t.Errorf("trigger channel length = %d, want 1 (coalesced)", len(reconciler.trigger))
	}
}

func TestSnapshotSortedByName(t *testing.T) {
	srv, reconciler := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})
	reconciler.nodeCache["n2"] = TailscaleNode{ID: "n2", Name: "alpha"}
	reconciler.nodeCache["n3"] = TailscaleNode{ID: "n3", Name: "zulu"}

	nodes := reconciler.Snapshot()
	if len(nodes) != 3 {
		t.Fatalf("snapshot length = %d, want 3", len(nodes))
	}
	if nodes[0].Name != "alpha" || nodes[2].Name != "zulu" {
		t.Errorf("snapshot not sorted: %v", []string{nodes[0].Name, nodes[1].Name, nodes[2].Name})
	}
	_ = srv
}

// ---------------------------------------------------------------------------
// TLS switch
// ---------------------------------------------------------------------------

func TestValidateTLSRequiresCertAndKey(t *testing.T) {
	base := func() *Config {
		return &Config{
			Tailscale: TailscaleConfig{APIKey: "k", Tailnet: "t"},
			DNS: DNSConfig{
				Provider: "cloudflare", Domain: "example.com", ZoneID: "z",
				Cloudflare: CloudflareConfig{APIToken: "t"},
			},
			App:     AppConfig{Workers: 2, PollInterval: 30 * time.Second},
			Logging: LoggingConfig{Level: "info", Format: "console"},
		}
	}

	t.Run("tls off needs no certs", func(t *testing.T) {
		cfg := base()
		cfg.API = APIConfig{Enabled: true, BindAddr: ":8080", TLSMode: "off"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.API.ServeHTTPS() {
			t.Error("ServeHTTPS() = true for off mode, want false")
		}
	})

	t.Run("tls provided without certs is rejected", func(t *testing.T) {
		cfg := base()
		cfg.API = APIConfig{Enabled: true, BindAddr: ":443", TLSMode: "provided"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected an error when api.tls_mode is \"provided\" without cert/key")
		}
	})

	t.Run("tls provided with certs passes", func(t *testing.T) {
		cfg := base()
		cfg.API = APIConfig{
			Enabled: true, BindAddr: ":443", TLSMode: "provided",
			TLSCert: "/cert.pem", TLSKey: "/key.pem",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !cfg.API.ServeHTTPS() {
			t.Error("ServeHTTPS() = false for provided mode, want true")
		}
	})

	t.Run("tls tailscale defaults the cert paths", func(t *testing.T) {
		cfg := base()
		cfg.API = APIConfig{Enabled: true, BindAddr: ":443", TLSMode: "tailscale"}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if cfg.API.TLSCert == "" || cfg.API.TLSKey == "" {
			t.Errorf("tailscale mode should default the cert paths, got %q/%q", cfg.API.TLSCert, cfg.API.TLSKey)
		}
		if !cfg.API.ServeHTTPS() {
			t.Error("ServeHTTPS() = false for tailscale mode, want true")
		}
	})

	t.Run("unknown tls mode is rejected", func(t *testing.T) {
		cfg := base()
		cfg.API = APIConfig{Enabled: true, TLSMode: "banana"}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected an error for an unknown api.tls_mode")
		}
	})
}

func TestServerConfigReportsTLSState(t *testing.T) {
	srv, _ := newTestServer(t, testDevicesResponse, http.StatusOK, &fakeProvider{})
	srv.cfg.Config.API.TLSMode = "provided"
	srv.cfg.Config.API.TLSCert = "/cert.pem"
	srv.cfg.Config.API.TLSKey = "/key.pem"

	rr := httptest.NewRecorder()
	srv.handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/config", nil))

	var body struct {
		API struct {
			HTTPS   bool   `json:"https"`
			TLSMode string `json:"tls_mode"`
			TLSCert string `json:"tls_cert"`
			TLSKey  string `json:"tls_key"`
		} `json:"api"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if !body.API.HTTPS {
		t.Errorf("api.https = false, want true")
	}
	if body.API.TLSMode != "provided" {
		t.Errorf("api.tls_mode = %q, want provided", body.API.TLSMode)
	}
	if body.API.TLSCert != "/cert.pem" || body.API.TLSKey != "/key.pem" {
		t.Errorf("api tls paths = %q/%q", body.API.TLSCert, body.API.TLSKey)
	}
}
