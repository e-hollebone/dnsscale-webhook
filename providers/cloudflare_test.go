package providers

// cloudflare_test.go — contract tests for the Cloudflare DNS provider.
//
// Each test stands up an httptest server that mimics the real Cloudflare API
// response shapes, then asserts both halves of the contract: the request the
// provider makes (method, path, auth header, body) and how it interprets the
// response. No test reaches the public API.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestCloudflare(t *testing.T, handler http.HandlerFunc) *CloudflareProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &CloudflareProvider{
		apiToken:   "cf-token-test",
		zoneID:     "zone-12345",
		httpClient: srv.Client(),
		baseURL:    srv.URL,
	}
}

func cloudflareOK(result interface{}) string {
	body, _ := json.Marshal(map[string]interface{}{
		"success":  true,
		"errors":   []interface{}{},
		"messages": []interface{}{},
		"result":   result,
	})
	return string(body)
}

func TestNewCloudflareProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		zone    string
		wantErr bool
	}{
		{"valid", "tok", "zone", false},
		{"missing token", "", "zone", true},
		{"missing zone", "tok", "", true},
		{"both missing", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewCloudflareProvider(tc.token, tc.zone)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewCloudflareProvider() = %v, want an error", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewCloudflareProvider() = %v", err)
			}
			if p == nil {
				t.Fatal("NewCloudflareProvider() returned a nil provider")
			}
		})
	}
}

func TestCloudflareListRecordsRequestAndConversion(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotUA string

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, cloudflareOK([]map[string]interface{}{
			{"id": "r1", "name": "web.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			{"id": "r2", "name": "web.example.com", "type": "AAAA", "content": "fd7a::1", "ttl": 300},
			{"id": "r3", "name": "web.example.com", "type": "TXT", "content": `"dnsscale-managed node_id=n1"`, "ttl": 300},
		}))
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}

	if gotMethod != http.MethodGet {
		t.Errorf("method = %s, want GET", gotMethod)
	}
	if gotPath != "/zones/zone-12345/dns_records" {
		t.Errorf("path = %q, want the zone records endpoint", gotPath)
	}
	if gotAuth != "Bearer cf-token-test" {
		t.Errorf("Authorization = %q, want the bearer token", gotAuth)
	}
	if gotUA != "dnsscale/1.0" {
		t.Errorf("User-Agent = %q, want dnsscale/1.0", gotUA)
	}

	if len(records) != 3 {
		t.Fatalf("records = %d, want 3: %+v", len(records), records)
	}
	if records[0].Name != "web.example.com" || records[0].Type != "A" || records[0].Value != "100.64.1.1" {
		t.Errorf("first record = %+v", records[0])
	}
	if records[0].TTL != 300 {
		t.Errorf("TTL = %d, want 300", records[0].TTL)
	}
}

func TestCloudflareListRecordsDropsUnsupportedTypes(t *testing.T) {
	// Only A, AAAA and TXT are managed. A CNAME or MX record in the zone must
	// never be returned, or the reconciler would try to delete it.
	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, cloudflareOK([]map[string]interface{}{
			{"id": "r1", "name": "web.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			{"id": "r2", "name": "web.example.com", "type": "CNAME", "content": "elsewhere.example.com", "ttl": 300},
			{"id": "r3", "name": "example.com", "type": "MX", "content": "mail.example.com", "ttl": 300},
		}))
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want only the A record: %+v", len(records), records)
	}
	if records[0].Type != "A" {
		t.Errorf("kept record type = %q, want A", records[0].Type)
	}
}

func TestCloudflareCreateRecord(t *testing.T) {
	var gotMethod, gotPath string
	var body map[string]interface{}

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		json.Unmarshal(raw, &body)
		fmt.Fprint(w, cloudflareOK(map[string]interface{}{"id": "new"}))
	})

	err := p.CreateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.1", TTL: 300,
	})
	if err != nil {
		t.Fatalf("CreateRecord() = %v", err)
	}

	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotPath != "/zones/zone-12345/dns_records" {
		t.Errorf("path = %q, want the collection endpoint", gotPath)
	}
	if body["name"] != "web.example.com" || body["type"] != "A" || body["content"] != "100.64.1.1" {
		t.Errorf("body = %+v, want the record fields", body)
	}
	// Tailscale addresses are private; proxying them through Cloudflare would
	// break resolution.
	if proxied, ok := body["proxied"].(bool); !ok || proxied {
		t.Errorf("proxied = %v, want false", body["proxied"])
	}
}

func TestCloudflareUpdateRecordUpdatesExisting(t *testing.T) {
	var methods []string
	var putPath string
	var putBody map[string]interface{}

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method+" "+r.URL.Path)

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/zone-12345/dns_records":
			// ListRecords: report the record as present.
			fmt.Fprint(w, cloudflareOK([]map[string]interface{}{
				{"id": "r1", "name": "web.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			}))
		case r.Method == http.MethodGet:
			// The lookup by name/type: return the id.
			fmt.Fprint(w, cloudflareOK([]map[string]interface{}{
				{"id": "r1", "name": "web.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			}))
		case r.Method == http.MethodPut:
			putPath = r.URL.Path
			raw, _ := io.ReadAll(r.Body)
			json.Unmarshal(raw, &putBody)
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{"id": "r1"}))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{}))
		}
	})

	err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.9", TTL: 300,
	})
	if err != nil {
		t.Fatalf("UpdateRecord() = %v", err)
	}

	if putPath != "/zones/zone-12345/dns_records/r1" {
		t.Errorf("PUT path = %q, want the record endpoint with its id", putPath)
	}
	if putBody["content"] != "100.64.1.9" {
		t.Errorf("PUT body = %+v, want the new address", putBody)
	}
}

func TestCloudflareUpdateRecordCreatesWhenMissing(t *testing.T) {
	var sawPost bool

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			// No existing record anywhere.
			fmt.Fprint(w, cloudflareOK([]map[string]interface{}{}))
		case r.Method == http.MethodPost:
			sawPost = true
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{"id": "new"}))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{}))
		}
	})

	err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "new.example.com", Type: "A", Value: "100.64.1.1", TTL: 300,
	})
	if err != nil {
		t.Fatalf("UpdateRecord() = %v", err)
	}
	if !sawPost {
		t.Error("UpdateRecord() did not fall back to creating the record")
	}
}

func TestCloudflareDeleteRecord(t *testing.T) {
	var deletedPath string

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet:
			fmt.Fprint(w, cloudflareOK([]map[string]interface{}{
				{"id": "r1", "name": "web.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			}))
		case r.Method == http.MethodDelete:
			deletedPath = r.URL.Path
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{"id": "r1"}))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})

	if err := p.DeleteRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.1",
	}); err != nil {
		t.Fatalf("DeleteRecord() = %v", err)
	}
	if deletedPath != "/zones/zone-12345/dns_records/r1" {
		t.Errorf("DELETE path = %q, want the record endpoint", deletedPath)
	}
}

func TestCloudflareDeleteRecordIsNoOpWhenAbsent(t *testing.T) {
	var sawDelete bool

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			sawDelete = true
		}
		fmt.Fprint(w, cloudflareOK([]map[string]interface{}{}))
	})

	if err := p.DeleteRecord(context.Background(), "example.com", DNSRecord{
		Name: "absent.example.com", Type: "A", Value: "100.64.1.1",
	}); err != nil {
		t.Fatalf("DeleteRecord() = %v", err)
	}
	if sawDelete {
		t.Error("DeleteRecord() issued a DELETE for a record that does not exist")
	}
}

func TestCloudflareAPIError(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			"error with details",
			`{"success":false,"errors":[{"code":1000,"message":"zone not found"}],"messages":[],"result":null}`,
			"cloudflare API error: zone not found (code: 1000)",
		},
		{
			"error without details",
			`{"success":false,"errors":[],"messages":[],"result":null}`,
			"cloudflare API request failed",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, tc.body)
			})
			_, err := p.ListRecords(context.Background(), "example.com")
			if err == nil {
				t.Fatal("ListRecords() = nil, want an error")
			}
			if err.Error() != tc.want {
				t.Errorf("error = %q, want %q", err.Error(), tc.want)
			}
		})
	}
}

func TestCloudflareMalformedResponse(t *testing.T) {
	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"success":true,"result":`)
	})
	if _, err := p.ListRecords(context.Background(), "example.com"); err == nil {
		t.Fatal("ListRecords() = nil for a truncated response, want an error")
	}
}

func TestCloudflareUsesRequestContext(t *testing.T) {
	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, cloudflareOK([]map[string]interface{}{}))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := p.ListRecords(ctx, "example.com"); err == nil {
		t.Fatal("ListRecords() = nil with a cancelled context, want an error")
	}
}

func cloudflareOKPaged(result []map[string]interface{}, page, totalPages int) string {
	body, _ := json.Marshal(map[string]interface{}{
		"success":  true,
		"errors":   []interface{}{},
		"messages": []interface{}{},
		"result":   result,
		"result_info": map[string]interface{}{
			"page":        page,
			"per_page":    100,
			"count":       len(result),
			"total_count": len(result) * totalPages,
			"total_pages": totalPages,
		},
	})
	return string(body)
}

// TestCloudflareListRecordsPaginates pins the behaviour that broke the live
// zone: Cloudflare pages the listing at 100 records per page and the zone
// holds 403. A single unpaginated call saw only the first 100, leaving every
// later record invisible, so the reconciler tried to create records that
// already existed.
func TestCloudflareListRecordsPaginates(t *testing.T) {
	var seenPages []string

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		seenPages = append(seenPages, page)
		switch page {
		case "1":
			fmt.Fprint(w, cloudflareOKPaged([]map[string]interface{}{
				{"id": "p1", "name": "one.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			}, 1, 2))
		case "2":
			fmt.Fprint(w, cloudflareOKPaged([]map[string]interface{}{
				{"id": "p2", "name": "two.example.com", "type": "A", "content": "100.64.1.2", "ttl": 300},
			}, 2, 2))
		default:
			t.Errorf("unexpected page requested: %q", page)
			fmt.Fprint(w, cloudflareOK([]map[string]interface{}{}))
		}
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}

	if len(seenPages) != 2 || seenPages[0] != "1" || seenPages[1] != "2" {
		t.Errorf("pages requested = %v, want [1 2]", seenPages)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want one from each page: %+v", len(records), records)
	}
	if records[1].Name != "two.example.com" {
		t.Errorf("second page record = %+v, want two.example.com", records[1])
	}
}

// TestCloudflareUpdateRecordSkipsIdenticalRecord pins the no-op guard: an
// unchanged record must not be PUT, because Cloudflare answers such a PUT with
// 81058 "An identical record already exists" and the reconciler logged that as
// a failure on every poll.
func TestCloudflareUpdateRecordSkipsIdenticalRecord(t *testing.T) {
	var putSeen bool

	p := newTestCloudflare(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, cloudflareOK([]map[string]interface{}{
				{"id": "r1", "name": "web.example.com", "type": "A", "content": "100.64.1.1", "ttl": 300},
			}))
		case http.MethodPut:
			putSeen = true
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{"id": "r1"}))
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			fmt.Fprint(w, cloudflareOK(map[string]interface{}{}))
		}
	})

	err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.1", TTL: 300,
	})
	if err != nil {
		t.Fatalf("UpdateRecord() = %v", err)
	}
	if putSeen {
		t.Error("UpdateRecord() issued a PUT for a record that was already correct")
	}
}
