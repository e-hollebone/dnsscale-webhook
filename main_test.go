package main

// main_test.go — coverage for the reconciler, the Tailscale API client and the
// startup helpers.
//
// The Tailscale API is replaced with an httptest server, so these tests assert
// the exact request the client makes (URL, encoding, headers) and how each
// response shape is handled. Nothing here touches the network.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/e-hollebone/dnsscale-with-webhook/providers"
	"go.uber.org/zap"
)

// recordingProvider captures every mutation so a test can assert what the
// reconciler actually published.
type recordingProvider struct {
	mu      sync.Mutex
	records []providers.DNSRecord
	deleted []providers.DNSRecord
	err     error
}

func (p *recordingProvider) ListRecords(ctx context.Context, zone string) ([]providers.DNSRecord, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return nil, p.err
	}
	return append([]providers.DNSRecord(nil), p.records...), nil
}

func (p *recordingProvider) CreateRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	return p.UpdateRecord(ctx, zone, record)
}

func (p *recordingProvider) UpdateRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.records = append(p.records, record)
	return nil
}

func (p *recordingProvider) DeleteRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.deleted = append(p.deleted, record)
	return nil
}

func (p *recordingProvider) snapshot() ([]providers.DNSRecord, []providers.DNSRecord) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]providers.DNSRecord(nil), p.records...), append([]providers.DNSRecord(nil), p.deleted...)
}

// newTailscaleTestClient builds a TailscaleClient pointed at a fake API.
func newTailscaleTestClient(t *testing.T, handler http.HandlerFunc) *TailscaleClient {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	return &TailscaleClient{
		apiKey:     "tskey-api-test",
		tailnet:    "example.ts.net",
		logger:     zap.NewNop(),
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}
}

// ---------------------------------------------------------------------------
// TailscaleDevice.ToTailscaleNode
// ---------------------------------------------------------------------------

func TestToTailscaleNode(t *testing.T) {
	recent := time.Now().Add(-time.Minute)
	stale := time.Now().Add(-time.Hour)

	tests := []struct {
		name       string
		device     TailscaleDevice
		wantName   string
		wantOnline bool
	}{
		{
			name:       "fqdn is truncated at the first dot",
			device:     TailscaleDevice{Name: "laptop.example.ts.net", Hostname: "laptop", LastSeen: recent},
			wantName:   "laptop",
			wantOnline: true,
		},
		{
			name:       "bare name is kept",
			device:     TailscaleDevice{Name: "web-server", Hostname: "web-server", LastSeen: recent},
			wantName:   "web-server",
			wantOnline: true,
		},
		{
			name:       "empty name falls back to hostname",
			device:     TailscaleDevice{Name: "", Hostname: "fallback", LastSeen: recent},
			wantName:   "fallback",
			wantOnline: true,
		},
		{
			name:       "a device unseen for over five minutes is offline",
			device:     TailscaleDevice{Name: "old", Hostname: "old", LastSeen: stale},
			wantName:   "old",
			wantOnline: false,
		},
		{
			name:       "zero LastSeen is offline",
			device:     TailscaleDevice{Name: "never", Hostname: "never"},
			wantName:   "never",
			wantOnline: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			node := tc.device.ToTailscaleNode()
			if node.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", node.Name, tc.wantName)
			}
			if node.Online != tc.wantOnline {
				t.Errorf("Online = %v, want %v", node.Online, tc.wantOnline)
			}
			if node.Hostname != tc.device.Hostname {
				t.Errorf("Hostname = %q, want %q", node.Hostname, tc.device.Hostname)
			}
			if len(node.Addresses) != len(tc.device.Addresses) {
				t.Errorf("Addresses = %v, want %v", node.Addresses, tc.device.Addresses)
			}
			if len(node.Tags) != len(tc.device.Tags) {
				t.Errorf("Tags = %v, want %v", node.Tags, tc.device.Tags)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TailscaleClient.ListNodes
// ---------------------------------------------------------------------------

func TestListNodesRequestShape(t *testing.T) {
	var gotPath, gotAuth, gotUA string

	client := newTailscaleTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"devices":[]}`)
	})

	nodes, err := client.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes() = %v", err)
	}
	if len(nodes) != 0 {
		t.Errorf("nodes = %v, want none", nodes)
	}
	if gotPath != "/api/v2/tailnet/example.ts.net/devices" {
		t.Errorf("path = %q, want the devices endpoint", gotPath)
	}
	if gotAuth != "Bearer tskey-api-test" {
		t.Errorf("Authorization = %q, want the bearer token", gotAuth)
	}
	if gotUA != "dnsscale/1.0" {
		t.Errorf("User-Agent = %q, want dnsscale/1.0", gotUA)
	}
}

func TestListNodesEncodesTailnet(t *testing.T) {
	// Tailnet names are frequently email addresses; the @ must be escaped or
	// the URL path is malformed. r.URL.Path is decoded by net/http, so the
	// escaped form has to be read back explicitly.
	var gotPath, gotEscaped string

	client := newTailscaleTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotEscaped = r.URL.EscapedPath()
		fmt.Fprint(w, `{"devices":[]}`)
	})
	client.tailnet = "example@gmail.com"

	if _, err := client.ListNodes(context.Background()); err != nil {
		t.Fatalf("ListNodes() = %v", err)
	}
	if !strings.Contains(gotEscaped, "example%40gmail.com") {
		t.Errorf("escaped path = %q, want the tailnet escaped as example%%40gmail.com", gotEscaped)
	}
	if !strings.Contains(gotPath, "example@gmail.com") {
		t.Errorf("decoded path = %q, want the tailnet present", gotPath)
	}
}

func TestListNodesSkipsUnauthorizedDevices(t *testing.T) {
	client := newTailscaleTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"devices":[
			{"id":"n1","name":"ok","hostname":"ok","authorized":true,"addresses":["100.64.1.1"],"lastSeen":"`+time.Now().Format(time.RFC3339)+`"},
			{"id":"n2","name":"blocked","hostname":"blocked","authorized":false,"addresses":["100.64.1.2"],"lastSeen":"`+time.Now().Format(time.RFC3339)+`"}
		]}`)
	})

	nodes, err := client.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes() = %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d, want 1 (unauthorized device skipped)", len(nodes))
	}
	if nodes[0].Name != "ok" {
		t.Errorf("node name = %q, want ok", nodes[0].Name)
	}
}

func TestListNodesErrors(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		body     string
		wantText string
	}{
		{"unauthorized", http.StatusUnauthorized, `{}`, "API request failed with status 401"},
		{"server error", http.StatusInternalServerError, `{}`, "API request failed with status 500"},
		{"malformed json", http.StatusOK, `{"devices": [`, "failed to decode API response"},
		{"wrong shape", http.StatusOK, `{"devices": "nope"}`, "failed to decode API response"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client := newTailscaleTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			})
			_, err := client.ListNodes(context.Background())
			if err == nil {
				t.Fatalf("ListNodes() = nil, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantText) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.wantText)
			}
		})
	}
}

func TestListNodesTransportError(t *testing.T) {
	// A closed server produces a transport error, not a status error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	client := &TailscaleClient{
		apiKey: "k", tailnet: "t", logger: zap.NewNop(),
		httpClient: srv.Client(), baseURL: srv.URL,
	}
	srv.Close()

	_, err := client.ListNodes(context.Background())
	if err == nil {
		t.Fatal("ListNodes() = nil, want a transport error")
	}
	if !strings.Contains(err.Error(), "failed to make API request") {
		t.Errorf("error = %q, want a transport error", err.Error())
	}
}

func TestListNodesUsesRequestContext(t *testing.T) {
	client := newTailscaleTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"devices":[]}`)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := client.ListNodes(ctx); err == nil {
		t.Fatal("ListNodes() = nil, want the cancelled context to abort the request")
	}
}

// ---------------------------------------------------------------------------
// DNSReconciler
// ---------------------------------------------------------------------------

func newTestReconciler(t *testing.T, apiBody string, provider providers.DNSProvider) (*DNSReconciler, *TailscaleClient) {
	t.Helper()
	client := newTailscaleTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, apiBody)
	})
	r := NewDNSReconciler(client, provider, "example.com", 30*time.Second, zap.NewNop())
	return r, client
}

func TestSyncNodesQueuesNewChangedAndDeleted(t *testing.T) {
	now := time.Now().Format(time.RFC3339)
	apiBody := fmt.Sprintf(`{"devices":[
		{"id":"n1","name":"alpha","hostname":"alpha","authorized":true,"addresses":["100.64.1.1"],"lastSeen":"%[1]s"},
		{"id":"n2","name":"beta","hostname":"beta","authorized":true,"addresses":["100.64.1.2"],"lastSeen":"%[1]s"}
	]}`, now)

	r, _ := newTestReconciler(t, apiBody, &recordingProvider{})

	// First pass: both nodes are new.
	r.syncNodes(context.Background())
	if got := queuedIDs(r); len(got) != 2 {
		t.Fatalf("first pass queued %v, want 2 items", got)
	}
	drain(r)

	// Second pass with identical state: nothing is queued.
	r.syncNodes(context.Background())
	if got := queuedIDs(r); len(got) != 0 {
		t.Fatalf("identical state queued %v, want none", got)
	}
	drain(r)

	// Third pass: n2's address changed, and n1 disappeared.
	apiBody = fmt.Sprintf(`{"devices":[
		{"id":"n2","name":"beta","hostname":"beta","authorized":true,"addresses":["100.64.1.99"],"lastSeen":"%[1]s"}
	]}`, now)
	r.tailscale = newTailscaleTestClient(t, func(w http.ResponseWriter, req *http.Request) {
		fmt.Fprint(w, apiBody)
	})

	r.syncNodes(context.Background())
	got := queuedIDs(r)
	if len(got) != 2 {
		t.Fatalf("changed+deleted pass queued %v, want 2 items", got)
	}
	sawUpdate, sawDelete := false, false
	for _, id := range got {
		if id == "n2" {
			sawUpdate = true
		}
		if id == "n1:delete" {
			sawDelete = true
		}
	}
	if !sawUpdate {
		t.Errorf("changed node n2 was not queued: %v", got)
	}
	if !sawDelete {
		t.Errorf("deleted node n1 was not queued as n1:delete: %v", got)
	}
}

func TestSyncNodesRecordsSyncTiming(t *testing.T) {
	r, _ := newTestReconciler(t, `{"devices":[]}`, &recordingProvider{})

	if stats := r.Stats(); stats.SyncCount != 0 || stats.LastSyncAt != nil {
		t.Fatalf("fresh reconciler stats = %+v, want zero", stats)
	}

	r.syncNodes(context.Background())
	stats := r.Stats()
	if stats.SyncCount != 1 {
		t.Errorf("sync count = %d, want 1", stats.SyncCount)
	}
	if stats.LastSyncAt == nil {
		t.Error("last sync at = nil, want a timestamp")
	}
}

func TestSyncNodesAPIFailureKeepsCacheAndStats(t *testing.T) {
	r, _ := newTestReconciler(t, `{"devices":[]}`, &recordingProvider{})
	r.nodeCache["keep"] = TailscaleNode{ID: "keep", Name: "keep"}

	// Replace the client with one that fails.
	r.tailscale = newTailscaleTestClient(t, func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	r.syncNodes(context.Background())

	if _, ok := r.nodeCache["keep"]; !ok {
		t.Error("cache lost its entry after an API failure")
	}
	if stats := r.Stats(); stats.SyncCount != 0 {
		t.Errorf("sync count = %d after a failed fetch, want 0", stats.SyncCount)
	}
}

func TestReconcileCreatesAddressAndOwnershipRecords(t *testing.T) {
	provider := &recordingProvider{}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)
	r.nodeCache["n1"] = TailscaleNode{
		ID: "n1", Name: "web-server", Hostname: "web-server",
		Addresses: []string{"100.64.1.1", "fd7a:115c:a1e0::1"}, Online: true,
	}

	if err := r.reconcile(context.Background(), "n1"); err != nil {
		t.Fatalf("reconcile() = %v", err)
	}

	records, _ := provider.snapshot()
	var sawA, sawAAAA, sawTXT bool
	for _, rec := range records {
		switch rec.Type {
		case "A":
			sawA = rec.Name == "web-server.example.com" && rec.Value == "100.64.1.1"
		case "AAAA":
			sawAAAA = rec.Name == "web-server.example.com" && rec.Value == "fd7a:115c:a1e0::1"
		case "TXT":
			sawTXT = strings.Contains(rec.Value, "dnsscale-managed") && strings.Contains(rec.Value, "node_id=n1")
		}
	}
	if !sawA {
		t.Errorf("no A record was published: %+v", records)
	}
	if !sawAAAA {
		t.Errorf("no AAAA record was published: %+v", records)
	}
	if !sawTXT {
		t.Errorf("no TXT ownership record was published: %+v", records)
	}
}

func TestReconcileUsesDomainFromConstructor(t *testing.T) {
	provider := &recordingProvider{}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)
	r.domain = "internal.example.org"
	r.nodeCache["n1"] = TailscaleNode{ID: "n1", Name: "host", Addresses: []string{"100.64.1.1"}}

	if err := r.reconcile(context.Background(), "n1"); err != nil {
		t.Fatalf("reconcile() = %v", err)
	}
	records, _ := provider.snapshot()
	if len(records) == 0 || records[0].Name != "host.internal.example.org" {
		t.Errorf("records = %+v, want the name under internal.example.org", records)
	}
}

func TestReconcilePropagatesProviderErrors(t *testing.T) {
	provider := &recordingProvider{err: fmt.Errorf("api down")}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)
	r.nodeCache["n1"] = TailscaleNode{ID: "n1", Name: "host", Addresses: []string{"100.64.1.1"}}

	err := r.reconcile(context.Background(), "n1")
	if err == nil {
		t.Fatal("reconcile() = nil, want the provider error")
	}
	if !strings.Contains(err.Error(), "failed to update DNS record") {
		t.Errorf("error = %q, want it to wrap the provider failure", err.Error())
	}
}

func TestReconcileSurvivesTXTFailure(t *testing.T) {
	// The TXT record is ownership metadata; a failure there must not fail the
	// address records that already succeeded.
	provider := &recordingProvider{}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)
	r.nodeCache["n1"] = TailscaleNode{ID: "n1", Name: "host", Addresses: []string{"100.64.1.1"}}

	failOnTXT := &txtFailingProvider{recordingProvider: provider}
	r.dnsProvider = failOnTXT

	if err := r.reconcile(context.Background(), "n1"); err != nil {
		t.Fatalf("reconcile() = %v, want nil (TXT failure is non-fatal)", err)
	}
}

type txtFailingProvider struct {
	*recordingProvider
}

func (p *txtFailingProvider) UpdateRecord(ctx context.Context, zone string, record providers.DNSRecord) error {
	if record.Type == "TXT" {
		return fmt.Errorf("txt unsupported")
	}
	return p.recordingProvider.UpdateRecord(ctx, zone, record)
}

func TestReconcileUnknownNode(t *testing.T) {
	r, _ := newTestReconciler(t, `{"devices":[]}`, &recordingProvider{})
	if err := r.reconcile(context.Background(), "missing"); err == nil {
		t.Fatal("reconcile() = nil, want an error for an unknown node id")
	}
}

func TestDeleteNodeDNSRemovesEveryRecordForTheName(t *testing.T) {
	provider := &recordingProvider{records: []providers.DNSRecord{
		{Name: "gone.example.com", Type: "A", Value: "100.64.1.1"},
		{Name: "gone.example.com", Type: "AAAA", Value: "fd7a::1"},
		{Name: "gone.example.com", Type: "TXT", Value: `"dnsscale-managed node_id=n1"`},
		{Name: "kept.example.com", Type: "A", Value: "100.64.1.2"},
	}}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)

	if err := r.deleteNodeDNS(context.Background(), "n1"); err != nil {
		t.Fatalf("deleteNodeDNS() = %v", err)
	}

	_, deleted := provider.snapshot()
	if len(deleted) != 3 {
		t.Fatalf("deleted %d records, want the 3 records for gone.example.com: %+v", len(deleted), deleted)
	}
	for _, rec := range deleted {
		if rec.Name != "gone.example.com" {
			t.Errorf("deleted %s, want only gone.example.com", rec.Name)
		}
	}
}

func TestDeleteNodeDNSWithoutOwnershipRecord(t *testing.T) {
	// A zone we do not manage must not be touched.
	provider := &recordingProvider{records: []providers.DNSRecord{
		{Name: "other.example.com", Type: "A", Value: "100.64.1.1"},
	}}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)

	if err := r.deleteNodeDNS(context.Background(), "n1"); err != nil {
		t.Fatalf("deleteNodeDNS() = %v", err)
	}
	if _, deleted := provider.snapshot(); len(deleted) != 0 {
		t.Errorf("deleted %+v, want nothing (no ownership record)", deleted)
	}
}

func TestShouldManageNode(t *testing.T) {
	r, _ := newTestReconciler(t, `{"devices":[]}`, &recordingProvider{})

	// No filter: everything is managed.
	if !r.shouldManageNode(TailscaleNode{Tags: nil}) {
		t.Error("with no tag filter, an untagged node should be managed")
	}

	r.annotations["tag:web"] = "true"

	if !r.shouldManageNode(TailscaleNode{Tags: []string{"tag:web"}}) {
		t.Error("a node carrying a required tag should be managed")
	}
	if r.shouldManageNode(TailscaleNode{Tags: []string{"tag:db"}}) {
		t.Error("a node without a required tag should not be managed")
	}
	if r.shouldManageNode(TailscaleNode{Tags: nil}) {
		t.Error("an untagged node should not be managed when a filter is set")
	}
}

func TestReconcileHonorsTagFilter(t *testing.T) {
	provider := &recordingProvider{}
	r, _ := newTestReconciler(t, `{"devices":[]}`, provider)
	r.annotations["tag:web"] = "true"
	r.nodeCache["n1"] = TailscaleNode{ID: "n1", Name: "db", Addresses: []string{"100.64.1.1"}, Tags: []string{"tag:db"}}

	if err := r.reconcile(context.Background(), "n1"); err != nil {
		t.Fatalf("reconcile() = %v", err)
	}
	if records, _ := provider.snapshot(); len(records) != 0 {
		t.Errorf("published %+v for a filtered-out node", records)
	}
}

func TestNodesEqual(t *testing.T) {
	base := TailscaleNode{Name: "a", Online: true, Addresses: []string{"100.64.1.1"}}

	tests := []struct {
		name string
		b    TailscaleNode
		want bool
	}{
		{"identical", base, true},
		{"different name", TailscaleNode{Name: "b", Online: true, Addresses: []string{"100.64.1.1"}}, false},
		{"different online state", TailscaleNode{Name: "a", Online: false, Addresses: []string{"100.64.1.1"}}, false},
		{"extra address", TailscaleNode{Name: "a", Online: true, Addresses: []string{"100.64.1.1", "100.64.1.2"}}, false},
		{"changed address", TailscaleNode{Name: "a", Online: true, Addresses: []string{"100.64.1.9"}}, false},
		{"reordered address", TailscaleNode{Name: "a", Online: true, Addresses: []string{"100.64.1.2", "100.64.1.1"}}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := nodesEqual(base, tc.b); got != tc.want {
				t.Errorf("nodesEqual() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestNodesEqualIgnoresTags(t *testing.T) {
	// Documented behaviour: a tag-only change does not re-queue a node. The
	// poll still converges because the cache entry is replaced each pass, but
	// the queue is not fed.
	a := TailscaleNode{Name: "a", Tags: []string{"tag:web"}}
	b := TailscaleNode{Name: "a", Tags: []string{"tag:db"}}
	if !nodesEqual(a, b) {
		t.Error("nodesEqual() = false for a tag-only change; the reconciler relies on this")
	}
}

func TestRunStopsOnContextCancel(t *testing.T) {
	r, _ := newTestReconciler(t, `{"devices":[]}`, &recordingProvider{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, 2) }()

	// Let the watcher and workers start, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != context.Canceled {
			t.Errorf("Run() = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run() did not return after the context was cancelled")
	}
}

// queuedIDs drains the workqueue and returns the item keys in order.
// Len() is checked first: Get() blocks while the queue is empty.
func queuedIDs(r *DNSReconciler) []string {
	var ids []string
	for r.queue.Len() > 0 {
		item, shutdown := r.queue.Get()
		if shutdown {
			break
		}
		ids = append(ids, item.(string))
		r.queue.Done(item)
		r.queue.Forget(item)
	}
	return ids
}

func drain(r *DNSReconciler) {
	for r.queue.Len() > 0 {
		item, shutdown := r.queue.Get()
		if shutdown {
			return
		}
		r.queue.Done(item)
		r.queue.Forget(item)
	}
}

// ---------------------------------------------------------------------------
// setupLogger
// ---------------------------------------------------------------------------

func TestSetupLoggerLevels(t *testing.T) {
	for _, level := range []string{"debug", "info", "warn", "error"} {
		logger, err := setupLogger(&LoggingConfig{Level: level, Format: "console"})
		if err != nil {
			t.Fatalf("setupLogger(%q) = %v", level, err)
		}
		if logger == nil {
			t.Fatalf("setupLogger(%q) returned a nil logger", level)
		}
		logger.Sync()
	}
}

func TestSetupLoggerFormats(t *testing.T) {
	for _, format := range []string{"json", "console", ""} {
		logger, err := setupLogger(&LoggingConfig{Level: "info", Format: format})
		if err != nil {
			t.Fatalf("setupLogger(format=%q) = %v", format, err)
		}
		logger.Sync()
	}
}

func TestSetupLoggerUnknownLevelStillBuilds(t *testing.T) {
	// Validate() rejects unknown levels before setupLogger is reached; the
	// helper itself must not panic if called directly.
	logger, err := setupLogger(&LoggingConfig{Level: "nonsense", Format: "console"})
	if err != nil {
		t.Fatalf("setupLogger() = %v", err)
	}
	logger.Sync()
}

// ---------------------------------------------------------------------------
// createDNSProvider
// ---------------------------------------------------------------------------

func TestCreateDNSProvider(t *testing.T) {
	ctx := context.Background()
	logger := zap.NewNop()

	t.Run("cloudflare", func(t *testing.T) {
		p, err := createDNSProvider(ctx, &Config{
			DNS: DNSConfig{Provider: "cloudflare", ZoneID: "zone-12345", Cloudflare: CloudflareConfig{APIToken: "tok"}},
		}, logger)
		if err != nil {
			t.Fatalf("createDNSProvider() = %v", err)
		}
		if _, ok := p.(*providers.CloudflareProvider); !ok {
			t.Errorf("provider type = %T, want *providers.CloudflareProvider", p)
		}
	})

	t.Run("pihole", func(t *testing.T) {
		p, err := createDNSProvider(ctx, &Config{
			DNS: DNSConfig{Provider: "pihole", Pihole: PiholeConfig{BaseURL: "http://pihole.local", APIToken: "tok"}},
		}, logger)
		if err != nil {
			t.Fatalf("createDNSProvider() = %v", err)
		}
		if _, ok := p.(*providers.PiholeProvider); !ok {
			t.Errorf("provider type = %T, want *providers.PiholeProvider", p)
		}
	})

	t.Run("cloudflare without a token", func(t *testing.T) {
		_, err := createDNSProvider(ctx, &Config{
			DNS: DNSConfig{Provider: "cloudflare"},
		}, logger)
		if err == nil {
			t.Fatal("createDNSProvider() = nil, want an error")
		}
	})

	t.Run("pihole without a url", func(t *testing.T) {
		_, err := createDNSProvider(ctx, &Config{
			DNS: DNSConfig{Provider: "pihole", Pihole: PiholeConfig{APIToken: "tok"}},
		}, logger)
		if err == nil {
			t.Fatal("createDNSProvider() = nil, want an error")
		}
	})

	t.Run("unknown provider", func(t *testing.T) {
		_, err := createDNSProvider(ctx, &Config{
			DNS: DNSConfig{Provider: "azure"},
		}, logger)
		if err == nil {
			t.Fatal("createDNSProvider() = nil, want an error")
		}
	})
}
