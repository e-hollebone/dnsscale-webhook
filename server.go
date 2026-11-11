package main

// server.go — the self-describing HTTP API for dnsscale.
//
// It serves two audiences, as required by the self-describing-api standard:
//
//	humans — GET /            HTML dashboard: attributes, functions, examples
//	agents — GET /api         JSON index, GET /api/v1/endpoints, GET /.well-known/dnsscale
//
// Every response carries RFC 8631 Link headers (service-doc, service-desc,
// status). Errors and empty results carry next_steps. Unknown paths return a
// JSON body pointing at the discovery endpoints. One endpoint table generates
// the index, the discovery document and the HTML page, so they cannot drift.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/e-hollebone/dnsscale-with-webhook/providers"
	"go.uber.org/zap"
)

const (
	serviceName    = "dnsscale"
	serviceVersion = "1.0.0"

	// webhookSignatureScheme is the only signature scheme Tailscale publishes.
	webhookSignatureScheme = "v1"
	// webhookMaxAge is the replay-protection window for webhook timestamps.
	// Tailscale's own documentation recommends rejecting events older than 5 minutes.
	webhookMaxAge = 5 * time.Minute
)

// endpoint describes one operation. It is the single source for the JSON index,
// the discovery document and the HTML page.
type endpoint struct {
	Name        string
	Method      string
	Path        string
	Description string
	Params      map[string]string
	Example     string
}

// endpoints is the operation table. Order is the order shown on the dashboard.
var endpoints = []endpoint{
	{
		Name:        "health",
		Method:      "GET",
		Path:        "/health",
		Description: "Health check: Tailscale API key, DNS provider token, sync freshness",
		Example:     `{"status":"healthy","checks":{"tailscale_api":"reachable","dns_provider":"reachable","node_count":80,"record_count":163},"metrics":{"sync_count":42,"last_sync_at":"2026-11-10T12:00:00Z","poll_interval":"30s","uptime":"2h 14m"}}`,
	},
	{
		Name:        "status",
		Method:      "GET",
		Path:        "/api/v1/status",
		Description: "Reconciler status: uptime, sync counters, poll interval, tag filters",
		Example:     `{"service":"dnsscale","version":"1.0.0","dns_provider":"cloudflare","dns_domain":"example.com","poll_interval":"30s","workers":2,"sync":{"sync_count":42,"last_sync_at":"2026-11-10T12:00:00Z","uptime":"2h 14m"},"nodes":{"count":80}}`,
	},
	{
		Name:        "config",
		Method:      "GET",
		Path:        "/api/v1/config",
		Description: "Effective configuration with every credential redacted",
		Example:     `{"tailscale":{"tailnet":"example.ts.net","api_key":"tske...ZZ4"},"dns":{"provider":"cloudflare","domain":"example.com","zone_id":"abc123def456"},"app":{"workers":2,"poll_interval":"30s","required_tags":[]}}`,
	},
	{
		Name:        "nodes",
		Method:      "GET",
		Path:        "/api/v1/nodes",
		Description: "Tailscale nodes currently known to the reconciler",
		Example:     `{"count":80,"nodes":[{"id":"n123","name":"web-server","hostname":"web-server","addresses":["100.64.1.1"],"tags":[],"online":true}]}`,
	},
	{
		Name:        "records",
		Method:      "GET",
		Path:        "/api/v1/records",
		Description: "DNS records currently published in the zone",
		Example:     `{"count":163,"records":[{"Name":"web-server.example.com","Type":"A","Value":"100.64.1.1","TTL":300}]}`,
	},
	{
		Name:        "sync",
		Method:      "POST",
		Path:        "/api/v1/sync",
		Description: "Trigger an immediate batch reconciliation now (the same pass the poll runs)",
		Example:     `{"triggered":true,"message":"Reconciliation pass queued; the reconciler will run it immediately.","last_sync_count":42}`,
	},
	{
		Name:        "webhook",
		Method:      "POST",
		Path:        "/api/v1/webhook",
		Description: "Tailscale webhook receiver (HMAC-verified fast-path)",
		Example:     `{"accepted":1,"types":["deviceCreated"],"triggered":true}`,
	},
}

// ServerConfig carries the dependencies the HTTP API needs.
type ServerConfig struct {
	BindAddr    string
	Webhook     WebhookConfig
	Reconciler  *DNSReconciler
	Tailscale   *TailscaleClient
	DNSProvider providers.DNSProvider
	Config      *Config
	Logger      *zap.Logger
}

// Server is the self-describing HTTP API for dnsscale.
type Server struct {
	cfg ServerConfig
}

// NewServer builds the HTTP API server.
func NewServer(cfg ServerConfig) *Server {
	return &Server{cfg: cfg}
}

// ListenAndServe starts the API. It blocks until the server stops.
func (s *Server) ListenAndServe() error {
	addr := s.cfg.BindAddr
	if addr == "" {
		addr = ":8080"
	}

	srv := &http.Server{
		Addr:              addr,
		Handler:           s.handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	if s.cfg.Config.API.ServeHTTPS() {
		s.cfg.Logger.Info("Starting dnsscale API (HTTPS)",
			zap.String("addr", addr),
			zap.String("mode", s.cfg.Config.API.TLSMode),
			zap.String("cert", s.cfg.Config.API.TLSCert),
			zap.String("key", s.cfg.Config.API.TLSKey))
		return srv.ListenAndServeTLS(s.cfg.Config.API.TLSCert, s.cfg.Config.API.TLSKey)
	}

	s.cfg.Logger.Info("Starting dnsscale API (HTTP)", zap.String("addr", addr))
	return srv.ListenAndServe()
}

// handler builds the route table and wraps it with the discovery middleware.
func (s *Server) handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", s.handleHealth)
	mux.HandleFunc("GET /api", s.handleAPIRoot)
	mux.HandleFunc("GET /api/v1/endpoints", s.handleEndpoints)
	mux.HandleFunc("GET /api/v1/status", s.handleStatus)
	mux.HandleFunc("GET /api/v1/config", s.handleConfig)
	mux.HandleFunc("GET /api/v1/nodes", s.handleNodes)
	mux.HandleFunc("GET /api/v1/records", s.handleRecords)
	mux.HandleFunc("POST /api/v1/sync", s.handleSync)
	mux.HandleFunc("POST "+s.webhookPath(), s.handleWebhook)
	mux.HandleFunc("GET /.well-known/dnsscale", s.handleWellKnown)

	// "/" is both the human dashboard and the catch-all: any other path is a 404
	// that points the caller at the discovery endpoints.
	mux.HandleFunc("/", s.handleRoot)

	return s.withDiscoveryHeaders(mux)
}

// webhookPath returns the configured webhook route, defaulting to the standard path.
func (s *Server) webhookPath() string {
	if s.cfg.Webhook.Path == "" {
		return "/api/v1/webhook"
	}
	return s.cfg.Webhook.Path
}

// withDiscoveryHeaders adds RFC 8631 Link relations and service identity to
// every response, so any client can discover the API from any response.
func (s *Server) withDiscoveryHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		base := s.baseURL(r)
		w.Header().Set("X-API-Version", serviceVersion)
		w.Header().Set("X-API-Service", serviceName)
		w.Header().Set("Link", fmt.Sprintf(
			`<%s/api/v1/endpoints>; rel="service-desc", <%s/>; rel="service-doc", <%s/health>; rel="status"`,
			base, base, base))
		next.ServeHTTP(w, r)
	})
}

// baseURL reconstructs the service's external base URL from the request.
func (s *Server) baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
		scheme = proto
	}
	return scheme + "://" + r.Host
}

// ---------------------------------------------------------------------------
// Human consumer
// ---------------------------------------------------------------------------

// handleRoot serves the HTML dashboard, or a discovery-pointing 404.
func (s *Server) handleRoot(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		s.writeError(w, r, http.StatusNotFound, "not_found",
			"Path not found",
			"GET /api/v1/endpoints to discover all available operations")
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, renderDashboard(s.baseURL(r)))
}

// ---------------------------------------------------------------------------
// Agent consumer — machine-readable discovery
// ---------------------------------------------------------------------------

// handleAPIRoot returns the JSON API index.
func (s *Server) handleAPIRoot(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"service":   serviceName,
		"version":   serviceVersion,
		"status":    "operational",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"endpoints": s.endpointIndex(),
		"discovery": map[string]string{
			"rfc_8631": "Link headers on every response: service-doc, service-desc, status",
			"rfc_5785": "/.well-known/dnsscale service metadata",
			"hateoas":  "Follow _links in responses for navigation",
		},
		"docs": map[string]string{
			"readme":   "README.md",
			"design":   "design.md",
			"upstream": "https://github.com/e-hollebone/dnsscale-with-webhook",
		},
		"code": map[string]string{
			"main":   "main.go",
			"server": "server.go",
		},
		"_links": map[string]string{
			"self":       "/api",
			"endpoints":  "/api/v1/endpoints",
			"well_known": "/.well-known/dnsscale",
			"docs":       "/",
		},
	})
}

// handleEndpoints returns the complete operation listing (HATEOAS discovery).
func (s *Server) handleEndpoints(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"service":   serviceName,
		"version":   serviceVersion,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"endpoints": s.endpointIndex(),
		"docs": map[string]string{
			"readme":   "README.md",
			"design":   "design.md",
			"upstream": "https://github.com/e-hollebone/dnsscale-with-webhook",
		},
		"_links": map[string]string{
			"self":       "/api/v1/endpoints",
			"index":      "/api",
			"well_known": "/.well-known/dnsscale",
			"docs":       "/",
		},
	})
}

// handleWellKnown returns RFC 5785 service metadata.
func (s *Server) handleWellKnown(w http.ResponseWriter, r *http.Request) {
	base := s.baseURL(r)
	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"service":  serviceName,
		"version":  serviceVersion,
		"api_root": "/api/v1",
		"endpoints": map[string]string{
			"description":   base + "/api/v1/endpoints",
			"index":         base + "/api",
			"documentation": base + "/",
			"health":        base + "/health",
		},
	})
}

// endpointIndex flattens the operation table into the discovery document.
func (s *Server) endpointIndex() map[string]interface{} {
	index := make(map[string]interface{}, len(endpoints))
	for _, e := range endpoints {
		entry := map[string]interface{}{
			"method":      e.Method,
			"path":        e.Path,
			"description": e.Description,
		}
		if len(e.Params) > 0 {
			entry["params"] = e.Params
		}
		if e.Example != "" {
			entry["example"] = e.Example
		}
		index[e.Name] = entry
	}
	return index
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

// handleHealth reports real dependency state, not just process uptime.
//   - unhealthy: the Tailscale API or the DNS provider is unreachable
//   - degraded:  reachable but no devices, or the last sync is stale
//   - healthy:   everything reachable and the last sync is fresh
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	status := "healthy"
	checks := map[string]interface{}{}
	metrics := map[string]interface{}{}

	nodeCount := 0
	nodes, err := s.cfg.Tailscale.ListNodes(ctx)
	if err != nil {
		checks["tailscale_api"] = "unreachable: " + err.Error()
		status = "unhealthy"
	} else {
		nodeCount = len(nodes)
		checks["tailscale_api"] = "reachable"
		checks["node_count"] = nodeCount
	}

	recordCount := 0
	records, err := s.cfg.DNSProvider.ListRecords(ctx, s.cfg.Config.DNS.Domain)
	if err != nil {
		checks["dns_provider"] = "unreachable: " + err.Error()
		status = "unhealthy"
	} else {
		recordCount = len(records)
		checks["dns_provider"] = "reachable"
		checks["record_count"] = recordCount
	}

	stats := s.cfg.Reconciler.Stats()
	metrics["sync_count"] = stats.SyncCount
	if stats.LastSyncAt != nil {
		metrics["last_sync_at"] = stats.LastSyncAt.UTC().Format(time.RFC3339)
	}
	metrics["poll_interval"] = s.cfg.Config.App.PollInterval.String()
	metrics["uptime"] = humanDuration(time.Since(stats.StartedAt))

	if status == "healthy" {
		switch {
		case nodeCount == 0:
			status = "degraded"
		case stats.LastSyncAt == nil:
			status = "degraded"
		case time.Since(*stats.LastSyncAt) > 2*s.cfg.Config.App.PollInterval:
			status = "degraded"
		}
	}

	code := http.StatusOK
	if status == "unhealthy" {
		code = http.StatusServiceUnavailable
	}

	s.writeJSON(w, r, code, map[string]interface{}{
		"status":    status,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"checks":    checks,
		"metrics":   metrics,
		"_links": map[string]string{
			"self":      "/health",
			"endpoints": "/api/v1/endpoints",
			"docs":      "/",
		},
	})
}

// handleStatus reports reconciler state and the effective runtime settings.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	stats := s.cfg.Reconciler.Stats()

	var lastSync interface{}
	if stats.LastSyncAt != nil {
		lastSync = stats.LastSyncAt.UTC().Format(time.RFC3339)
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"service":         serviceName,
		"version":         serviceVersion,
		"timestamp":       time.Now().UTC().Format(time.RFC3339),
		"dns_provider":    s.cfg.Config.DNS.Provider,
		"dns_domain":      s.cfg.Config.DNS.Domain,
		"poll_interval":   s.cfg.Config.App.PollInterval.String(),
		"workers":         s.cfg.Config.App.Workers,
		"required_tags":   s.cfg.Config.App.RequiredTags,
		"api_enabled":     s.cfg.Config.API.Enabled,
		"webhook_enabled": s.cfg.Config.Webhook.Enabled,
		"sync": map[string]interface{}{
			"sync_count":   stats.SyncCount,
			"started_at":   stats.StartedAt.UTC().Format(time.RFC3339),
			"last_sync_at": lastSync,
			"uptime":       humanDuration(time.Since(stats.StartedAt)),
		},
		"nodes": map[string]interface{}{
			"count": len(s.cfg.Reconciler.Snapshot()),
		},
		"_links": map[string]string{
			"self":      "/api/v1/status",
			"health":    "/health",
			"endpoints": "/api/v1/endpoints",
		},
	})
}

// handleConfig returns the effective configuration with credentials masked.
func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg.Config

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"tailscale": map[string]interface{}{
			"tailnet": cfg.Tailscale.Tailnet,
			"api_key": redact(cfg.Tailscale.APIKey),
		},
		"dns": map[string]interface{}{
			"provider": cfg.DNS.Provider,
			"domain":   cfg.DNS.Domain,
			"zone_id":  cfg.DNS.ZoneID,
			"cloudflare": map[string]interface{}{
				"api_token": redact(cfg.DNS.Cloudflare.APIToken),
			},
			"route53": map[string]interface{}{
				"profile": cfg.DNS.Route53.Profile,
				"region":  cfg.DNS.Route53.Region,
			},
			"pihole": map[string]interface{}{
				"base_url":  cfg.DNS.Pihole.BaseURL,
				"api_token": redact(cfg.DNS.Pihole.APIToken),
			},
		},
		"app": map[string]interface{}{
			"workers":       cfg.App.Workers,
			"poll_interval": cfg.App.PollInterval.String(),
			"required_tags": cfg.App.RequiredTags,
		},
		"logging": map[string]interface{}{
			"level":  cfg.Logging.Level,
			"format": cfg.Logging.Format,
		},
		"api": map[string]interface{}{
			"enabled":   cfg.API.Enabled,
			"bind_addr": cfg.API.BindAddr,
			"https":     cfg.API.ServeHTTPS(),
			"tls_mode":  cfg.API.TLSMode,
			"tls_cert":  cfg.API.TLSCert,
			"tls_key":   cfg.API.TLSKey,
		},
		"webhook": map[string]interface{}{
			"enabled": cfg.Webhook.Enabled,
			"path":    s.webhookPath(),
			"secret":  redact(cfg.Webhook.Secret),
		},
		"_links": map[string]string{
			"self":      "/api/v1/config",
			"endpoints": "/api/v1/endpoints",
			"docs":      "/",
		},
	})
}

// handleNodes returns the reconciler's current view of the tailnet.
func (s *Server) handleNodes(w http.ResponseWriter, r *http.Request) {
	nodes := s.cfg.Reconciler.Snapshot()
	if nodes == nil {
		nodes = []TailscaleNode{}
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"count": len(nodes),
		"nodes": nodes,
		"_links": map[string]string{
			"self":      "/api/v1/nodes",
			"endpoints": "/api/v1/endpoints",
		},
	})
}

// handleRecords returns the DNS records currently published in the zone.
func (s *Server) handleRecords(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	records, err := s.cfg.DNSProvider.ListRecords(ctx, s.cfg.Config.DNS.Domain)
	if err != nil {
		s.writeError(w, r, http.StatusBadGateway, "dns_provider_error",
			"Failed to list DNS records", err.Error())
		return
	}
	if records == nil {
		records = []providers.DNSRecord{}
	}

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"count":   len(records),
		"records": records,
		"_links": map[string]string{
			"self":      "/api/v1/records",
			"endpoints": "/api/v1/endpoints",
		},
	})
}

// handleSync triggers an immediate reconciliation pass.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	lastCount := s.cfg.Reconciler.Stats().SyncCount
	s.cfg.Reconciler.TriggerSync()
	s.cfg.Logger.Info("Sync triggered via API", zap.String("remote_addr", r.RemoteAddr))

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"triggered":       true,
		"last_sync_count": lastCount,
		"message":         "Reconciliation pass queued; the reconciler will run it immediately.",
		"_links": map[string]string{
			"self":   "/api/v1/sync",
			"status": "/api/v1/status",
		},
	})
}

// ---------------------------------------------------------------------------
// Tailscale webhook receiver
// ---------------------------------------------------------------------------

// webhookEvent is one Tailscale webhook event. The request body is always a
// JSON array of these (Tailscale docs, "Events payload").
type webhookEvent struct {
	Timestamp string `json:"timestamp"`
	Version   int    `json:"version"`
	Type      string `json:"type"`
	Tailnet   string `json:"tailnet"`
	Message   string `json:"message"`
	Actor     string `json:"actor,omitempty"`
}

// handleWebhook verifies the Tailscale signature and fast-paths a sync.
// The poll ticker stays authoritative: Tailscale has no rename event, so the
// periodic reconciliation remains the only path that converges renames.
func (s *Server) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Webhook.Enabled {
		s.writeError(w, r, http.StatusNotFound, "webhook_disabled",
			"Webhook receiver is not enabled",
			"Set webhook.enabled=true and webhook.secret to receive Tailscale events.")
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, r, http.StatusBadRequest, "bad_request",
			"Failed to read request body", err.Error())
		return
	}
	defer r.Body.Close()

	events, err := verifyWebhookSignature(r, body, s.cfg.Webhook.Secret)
	if err != nil {
		s.cfg.Logger.Warn("Rejected webhook",
			zap.Error(err), zap.String("remote_addr", r.RemoteAddr))
		s.writeError(w, r, http.StatusUnauthorized, "invalid_signature",
			"Webhook signature verification failed", err.Error())
		return
	}

	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, e.Type)
	}
	s.cfg.Logger.Info("Accepted Tailscale webhook",
		zap.Int("events", len(events)), zap.Strings("types", types))

	s.cfg.Reconciler.TriggerSync()

	s.writeJSON(w, r, http.StatusOK, map[string]interface{}{
		"accepted":  len(events),
		"types":     types,
		"triggered": true,
		"_links": map[string]string{
			"self":      s.webhookPath(),
			"endpoints": "/api/v1/endpoints",
		},
	})
}

// verifyWebhookSignature checks the Tailscale-Webhook-Signature header against
// the raw request body using HMAC-SHA256, and rejects stale timestamps.
//
// Header format (Tailscale docs): "t=<epoch>,v1=<hex>"
// Signed content: "<epoch>.<raw body>"
// v1 is the only scheme Tailscale publishes.
func verifyWebhookSignature(r *http.Request, body []byte, secret string) ([]webhookEvent, error) {
	header := r.Header.Get("Tailscale-Webhook-Signature")
	if header == "" {
		return nil, fmt.Errorf("request has no signature")
	}

	var timestamp int64
	var signature string
	for _, part := range strings.Split(header, ",") {
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "t":
			parsed, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid timestamp in signature header")
			}
			timestamp = parsed
		case webhookSignatureScheme:
			signature = strings.TrimSpace(value)
		}
	}
	if timestamp == 0 || signature == "" {
		return nil, fmt.Errorf("signature header missing t= or v1=")
	}

	if time.Since(time.Unix(timestamp, 0)) > webhookMaxAge {
		return nil, fmt.Errorf("timestamp older than %s (possible replay)", webhookMaxAge)
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(timestamp, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(signature), []byte(expected)) != 1 {
		return nil, fmt.Errorf("signature does not match")
	}

	var events []webhookEvent
	if err := json.Unmarshal(body, &events); err != nil {
		return nil, fmt.Errorf("failed to decode events payload: %w", err)
	}
	return events, nil
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

// writeJSON emits a JSON response with the given status code.
func (s *Server) writeJSON(w http.ResponseWriter, r *http.Request, status int, body interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		s.cfg.Logger.Warn("Failed to encode JSON response", zap.Error(err))
	}
}

// writeError emits a structured error with the discovery endpoints as next_steps.
func (s *Server) writeError(w http.ResponseWriter, r *http.Request, status int, code, message, hint string) {
	s.writeJSON(w, r, status, map[string]interface{}{
		"error": map[string]interface{}{
			"code":    code,
			"message": message,
			"hint":    hint,
		},
		"api_version": serviceVersion,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"next_steps": []string{
			"GET /api/v1/endpoints — discover all operations",
			"GET / — human-readable documentation",
		},
	})
}

// redact masks a credential so the config endpoint never returns it in full.
func redact(value string) string {
	if value == "" {
		return ""
	}
	if len(value) <= 8 {
		return "***"
	}
	return value[:4] + "..." + value[len(value)-4:]
}

// humanDuration renders a duration as a short human-readable string.
func humanDuration(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Truncate(time.Second)

	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	return strings.Join(parts, " ")
}
