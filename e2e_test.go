package main

// e2e_test.go — end-to-end tests that exercise the real binary.
//
// The suite builds the dnsscale executable, starts fake Tailscale and
// Cloudflare APIs, writes a real configuration file and drives the running
// process over HTTP. This covers the layers the unit tests cannot: CLI flag
// parsing, viper config loading, provider selection, the reconciler loop and
// the live HTTP listener including TLS.
//
// Nothing here reaches a real external service. TAILSCALE_API_URL and
// CLOUDFLARE_API_URL redirect the clients at the fakes.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeTailscale answers the device list endpoint.
type fakeTailscale struct {
	mu      sync.Mutex
	devices []map[string]interface{}
	calls   int
}

func (f *fakeTailscale) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.calls++
		devices := append([]map[string]interface{}(nil), f.devices...)
		f.mu.Unlock()

		if got := r.Header.Get("Authorization"); got != "Bearer tskey-api-e2e" {
			t.Errorf("Tailscale API received Authorization = %q", got)
		}
		if !strings.Contains(r.URL.Path, "/api/v2/tailnet/") || !strings.HasSuffix(r.URL.Path, "/devices") {
			t.Errorf("Tailscale API received path = %q", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"devices": devices})
	}
}

func (f *fakeTailscale) setDevices(devices ...map[string]interface{}) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices = devices
}

// fakeCloudflare is an in-memory Cloudflare DNS API.
type fakeCloudflare struct {
	mu       sync.Mutex
	records  map[string]map[string]interface{}
	nextID   int
	requests []string
}

func newFakeCloudflare() *fakeCloudflare {
	return &fakeCloudflare{records: map[string]map[string]interface{}{}}
}

func (f *fakeCloudflare) handler(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
		f.mu.Unlock()

		if got := r.Header.Get("Authorization"); got != "Bearer cf-token-e2e" {
			t.Errorf("Cloudflare API received Authorization = %q", got)
		}

		path := r.URL.Path
		parts := strings.Split(strings.TrimPrefix(path, "/zones/zone-e2e/dns_records"), "/")
		id := ""
		if len(parts) > 1 {
			id = parts[1]
		}

		w.Header().Set("Content-Type", "application/json")

		switch r.Method {
		case http.MethodGet:
			f.mu.Lock()
			defer f.mu.Unlock()
			out := []map[string]interface{}{}
			for _, rec := range f.records {
				if name := r.URL.Query().Get("name"); name != "" && rec["name"] != name {
					continue
				}
				if typ := r.URL.Query().Get("type"); typ != "" && rec["type"] != typ {
					continue
				}
				out = append(out, rec)
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "errors": []interface{}{}, "messages": []interface{}{},
				"result": out,
			})

		case http.MethodPost:
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			defer f.mu.Unlock()
			f.nextID++
			rec := map[string]interface{}{
				"id":      fmt.Sprintf("rec-%d", f.nextID),
				"name":    body["name"],
				"type":    body["type"],
				"content": body["content"],
				"ttl":     body["ttl"],
			}
			f.records[rec["id"].(string)] = rec
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "errors": []interface{}{}, "messages": []interface{}{},
				"result": rec,
			})

		case http.MethodPut:
			var body map[string]interface{}
			json.NewDecoder(r.Body).Decode(&body)
			f.mu.Lock()
			defer f.mu.Unlock()
			rec, ok := f.records[id]
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]interface{}{
					"success": false, "errors": []map[string]interface{}{{"code": 1000, "message": "not found"}},
				})
				return
			}
			rec["name"] = body["name"]
			rec["type"] = body["type"]
			rec["content"] = body["content"]
			rec["ttl"] = body["ttl"]
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "errors": []interface{}{}, "messages": []interface{}{},
				"result": rec,
			})

		case http.MethodDelete:
			f.mu.Lock()
			defer f.mu.Unlock()
			delete(f.records, id)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true, "errors": []interface{}{}, "messages": []interface{}{},
				"result": map[string]interface{}{"id": id},
			})

		default:
			t.Errorf("Cloudflare API received method = %q", r.Method)
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}
}

func (f *fakeCloudflare) snapshot() map[string]map[string]interface{} {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]map[string]interface{}{}
	for k, v := range f.records {
		out[k] = v
	}
	return out
}

// ---------------------------------------------------------------------------
// Binary under test
// ---------------------------------------------------------------------------

// buildBinary compiles the real executable once per test run.
func buildBinary(t *testing.T) string {
	t.Helper()

	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("the end-to-end suite needs the go tool on PATH")
	}

	_, thisFile, _, _ := runtime.Caller(0)
	srcDir := filepath.Dir(thisFile)
	out := filepath.Join(t.TempDir(), "dnsscale")

	cmd := exec.Command(goBin, "build", "-o", out, ".")
	cmd.Dir = srcDir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building dnsscale: %v\n%s", err, out)
	}
	return out
}

// e2eEnv carries everything a running instance needs.
type e2eEnv struct {
	cmd       *exec.Cmd
	baseURL   string
	apiURL    string
	configDir string
}

// childEnv builds a minimal, explicit environment for the process under test.
//
// Ambient variables must never reach the binary. Viper gives the environment
// precedence over the config file, so an inherited TAILSCALE_API_KEY or
// API_TLS_MODE would silently replace the fixture — and a real key would be
// sent to the fake endpoint and printed in the test log.
func childEnv(extra map[string]string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GOTOOLCHAIN=local",
	}
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

// startInstance launches the binary against the fakes and waits for health.
func startInstance(t *testing.T, binary string, ts *fakeTailscale, cf *fakeCloudflare, tlsMode, certFile, keyFile string) *e2eEnv {
	t.Helper()

	tsServer := httptest.NewServer(ts.handler(t))
	t.Cleanup(tsServer.Close)
	cfServer := httptest.NewServer(cf.handler(t))
	t.Cleanup(cfServer.Close)

	port := freePort(t)
	configDir := t.TempDir()
	configPath := filepath.Join(configDir, "dnsscale.yaml")

	config := fmt.Sprintf(`tailscale:
  api_key: "tskey-api-e2e"
  tailnet: "e2e.ts.net"
dns:
  provider: "cloudflare"
  domain: "e2e.example.com"
  zone_id: "zone-e2e"
  cloudflare:
    api_token: "cf-token-e2e"
app:
  workers: 2
  poll_interval: "2s"
logging:
  level: "info"
  format: "console"
api:
  enabled: true
  bind_addr: "127.0.0.1:%d"
  tls_mode: "%s"
  tls_cert: "%s"
  tls_key: "%s"
webhook:
  enabled: true
  secret: "e2e-webhook-secret"
  path: "/api/v1/webhook"
`, port, tlsMode, certFile, keyFile)

	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("writing the config: %v", err)
	}

	cmd := exec.Command(binary, "--config", configPath)
	cmd.Env = childEnv(map[string]string{
		"TAILSCALE_API_URL":  tsServer.URL,
		"CLOUDFLARE_API_URL": cfServer.URL,
	})
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard

	if err := cmd.Start(); err != nil {
		t.Fatalf("starting dnsscale: %v", err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
	})

	scheme := "http"
	if tlsMode != "off" {
		scheme = "https"
	}
	env := &e2eEnv{
		cmd:       cmd,
		baseURL:   fmt.Sprintf("%s://127.0.0.1:%d", scheme, port),
		apiURL:    cfServer.URL,
		configDir: configDir,
	}

	waitForHealth(t, env.baseURL, tlsMode != "off")
	return env
}

// freePort asks the kernel for an unused TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("finding a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// httpClient returns a client that tolerates the self-signed test certificate.
func httpClient(insecure bool) *http.Client {
	if !insecure {
		return &http.Client{Timeout: 5 * time.Second}
	}
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test fixture
		},
	}
}

func waitForHealth(t *testing.T, baseURL string, insecure bool) {
	t.Helper()
	client := httpClient(insecure)
	deadline := time.Now().Add(20 * time.Second)

	for time.Now().Before(deadline) {
		resp, err := client.Get(baseURL + "/health")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dnsscale did not become healthy at %s", baseURL)
}

func getJSON(t *testing.T, baseURL, path string, insecure bool, out interface{}) int {
	t.Helper()
	client := httpClient(insecure)
	resp, err := client.Get(baseURL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if out != nil && resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, out); err != nil {
			t.Fatalf("GET %s returned invalid JSON: %v\n%s", path, err, body)
		}
	}
	return resp.StatusCode
}

func postJSON(t *testing.T, baseURL, path string, body []byte, headers map[string]string, insecure bool) (int, []byte) {
	t.Helper()
	client := httpClient(insecure)
	req, err := http.NewRequest(http.MethodPost, baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatalf("building POST %s: %v", path, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// writeSelfSignedCert generates a throwaway certificate for the TLS test.
func writeSelfSignedCert(t *testing.T, dir string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "dnsscale-e2e"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost", "dnsscale-e2e"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the certificate: %v", err)
	}

	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling the key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("writing the certificate: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("writing the key: %v", err)
	}
	return certPath, keyPath
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestE2EPlainTextMode(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{
		device("n1", "web-server", []string{"100.64.1.1"}),
	}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)

	env := startInstance(t, binary, ts, cf, "off", "", "")

	var health struct {
		Status string                 `json:"status"`
		Checks map[string]interface{} `json:"checks"`
	}
	if code := getJSON(t, env.baseURL, "/health", false, &health); code != http.StatusOK {
		t.Fatalf("GET /health = %d, want 200", code)
	}
	if health.Status != "healthy" {
		t.Errorf("status = %q, want healthy; checks=%v", health.Status, health.Checks)
	}
	if health.Checks["tailscale_api"] != "reachable" {
		t.Errorf("tailscale_api = %v, want reachable", health.Checks["tailscale_api"])
	}

	var nodes struct {
		Count int `json:"count"`
	}
	getJSON(t, env.baseURL, "/api/v1/nodes", false, &nodes)
	if nodes.Count != 1 {
		t.Errorf("nodes = %d, want 1", nodes.Count)
	}

	// The reconciler polls every 2s, so give it a pass and then check the
	// records it published.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if len(cf.snapshot()) > 0 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	records := cf.snapshot()
	if len(records) == 0 {
		t.Fatal("the reconciler published no DNS records")
	}
	var sawA, sawTXT bool
	for _, rec := range records {
		if rec["name"] == "web-server.e2e.example.com" && rec["type"] == "A" && rec["content"] == "100.64.1.1" {
			sawA = true
		}
		if rec["type"] == "TXT" && strings.Contains(fmt.Sprint(rec["content"]), "dnsscale-managed") {
			sawTXT = true
		}
	}
	if !sawA {
		t.Errorf("no A record was published: %+v", records)
	}
	if !sawTXT {
		t.Errorf("no TXT ownership record was published: %+v", records)
	}
}

func TestE2EHTTPSMode(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{
		device("n1", "web-server", []string{"100.64.1.1"}),
	}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)

	certFile, keyFile := writeSelfSignedCert(t, t.TempDir())
	env := startInstance(t, binary, ts, cf, "provided", certFile, keyFile)

	// HTTPS must serve.
	var health struct {
		Status string `json:"status"`
	}
	if code := getJSON(t, env.baseURL, "/health", true, &health); code != http.StatusOK {
		t.Fatalf("GET https://…/health = %d, want 200", code)
	}

	// Plain HTTP against the TLS listener must not return a successful API
	// response. Go's TLS server answers with a 400 rather than a transport
	// error, so the status code is what has to be checked.
	plain := strings.Replace(env.baseURL, "https://", "http://", 1)
	resp, err := http.Get(plain + "/health")
	if err != nil {
		// A transport-level failure is also a correct rejection.
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		t.Errorf("plain HTTP got a 200 from the HTTPS listener: %s", body)
	}

	// The running service must report that it is serving HTTPS.
	var cfg struct {
		API struct {
			HTTPS   bool   `json:"https"`
			TLSMode string `json:"tls_mode"`
		} `json:"api"`
	}
	getJSON(t, env.baseURL, "/api/v1/config", true, &cfg)
	if !cfg.API.HTTPS {
		t.Errorf("api.https = false, want true in provided mode")
	}
	if cfg.API.TLSMode != "provided" {
		t.Errorf("api.tls_mode = %q, want provided", cfg.API.TLSMode)
	}
}

func TestE2EWebhookRoundTrip(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{
		device("n1", "web-server", []string{"100.64.1.1"}),
	}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)
	env := startInstance(t, binary, ts, cf, "off", "", "")

	// A valid, signed webhook must be accepted.
	body := []byte(`[{"timestamp":"2026-11-10T12:00:00Z","version":1,"type":"deviceCreated","tailnet":"e2e.ts.net","message":"node created"}]`)
	mac := hmac.New(sha256.New, []byte("e2e-webhook-secret"))
	mac.Write([]byte(fmt.Sprint(time.Now().Unix())))
	mac.Write([]byte("."))
	mac.Write(body)
	sig := "t=" + fmt.Sprint(time.Now().Unix()) + ",v1=" + hex.EncodeToString(mac.Sum(nil))

	code, raw := postJSON(t, env.baseURL, "/api/v1/webhook", body, map[string]string{
		"Tailscale-Webhook-Signature": sig,
	}, false)
	if code != http.StatusOK {
		t.Fatalf("POST /api/v1/webhook = %d, want 200; body=%s", code, raw)
	}

	// A webhook signed with the wrong secret must be rejected.
	mac = hmac.New(sha256.New, []byte("wrong-secret"))
	mac.Write([]byte("12345"))
	mac.Write([]byte("."))
	mac.Write(body)
	badSig := "t=12345,v1=" + hex.EncodeToString(mac.Sum(nil))

	code, raw = postJSON(t, env.baseURL, "/api/v1/webhook", body, map[string]string{
		"Tailscale-Webhook-Signature": badSig,
	}, false)
	if code != http.StatusUnauthorized {
		t.Errorf("POST /api/v1/webhook with a bad signature = %d, want 401; body=%s", code, raw)
	}
}

func TestE2ESyncTrigger(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{
		device("n1", "web-server", []string{"100.64.1.1"}),
	}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)
	env := startInstance(t, binary, ts, cf, "off", "", "")

	code, raw := postJSON(t, env.baseURL, "/api/v1/sync", nil, nil, false)
	if code != http.StatusOK {
		t.Fatalf("POST /api/v1/sync = %d, want 200; body=%s", code, raw)
	}

	var resp struct {
		Triggered bool `json:"triggered"`
	}
	json.Unmarshal(raw, &resp)
	if !resp.Triggered {
		t.Errorf("triggered = false, want true; body=%s", raw)
	}
}

func TestE2EConfigRedactsCredentials(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)
	env := startInstance(t, binary, ts, cf, "off", "", "")

	client := httpClient(false)
	resp, err := client.Get(env.baseURL + "/api/v1/config")
	if err != nil {
		t.Fatalf("GET /api/v1/config: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	for _, secret := range []string{"tskey-api-e2e", "cf-token-e2e", "e2e-webhook-secret"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("the config endpoint leaked %q: %s", secret, raw)
		}
	}
}

func TestE2ENodeChangesPropagate(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{
		device("n1", "web-server", []string{"100.64.1.1"}),
	}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)
	env := startInstance(t, binary, ts, cf, "off", "", "")

	// Change the tailnet behind the process's back, then trigger a sync.
	ts.setDevices(device("n1", "web-server", []string{"100.64.1.99"}))
	postJSON(t, env.baseURL, "/api/v1/sync", nil, nil, false)

	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, rec := range cf.snapshot() {
			if rec["type"] == "A" && rec["content"] == "100.64.1.99" {
				return // the change propagated
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("the address change never reached the DNS provider: %+v", cf.snapshot())
}

func TestE2EDiscoveryDocuments(t *testing.T) {
	ts := &fakeTailscale{devices: []map[string]interface{}{}}
	cf := newFakeCloudflare()
	binary := buildBinary(t)
	env := startInstance(t, binary, ts, cf, "off", "", "")

	client := httpClient(false)
	for _, path := range []string{"/api", "/api/v1/endpoints", "/.well-known/dnsscale"} {
		resp, err := client.Get(env.baseURL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want 200", path, resp.StatusCode)
		}
		var doc map[string]interface{}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Errorf("GET %s is not valid JSON: %v", path, err)
		}
		if resp.Header.Get("Link") == "" {
			t.Errorf("GET %s has no Link header", path)
		}
	}
}

// device builds a Tailscale API device document.
func device(id, name string, addresses []string) map[string]interface{} {
	return map[string]interface{}{
		"id":         id,
		"name":       name + ".e2e.ts.net",
		"hostname":   name,
		"authorized": true,
		"addresses":  addresses,
		"lastSeen":   time.Now().Format(time.RFC3339),
	}
}
