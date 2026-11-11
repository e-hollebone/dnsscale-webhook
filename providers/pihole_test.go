package providers

// pihole_test.go — contract tests for the Pi-hole DNS provider.
//
// Pi-hole's custom DNS API is a PHP form endpoint with its own conventions
// (auth in the query for GET, in the body for POST; a nested `data` array).
// These tests pin those conventions down so a Pi-hole API change cannot pass
// silently.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func newTestPihole(t *testing.T, handler http.HandlerFunc) *PiholeProvider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return &PiholeProvider{
		baseURL:    srv.URL,
		apiToken:   "pihole-token-test",
		httpClient: srv.Client(),
	}
}

func TestNewPiholeProviderValidation(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		token   string
		wantErr bool
	}{
		{"valid", "http://pihole.local", "tok", false},
		{"missing base url", "", "tok", true},
		{"missing token", "http://pihole.local", "", true},
		{"both missing", "", "", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p, err := NewPiholeProvider(tc.baseURL, tc.token)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NewPiholeProvider() = %v, want an error", p)
				}
				return
			}
			if err != nil {
				t.Fatalf("NewPiholeProvider() = %v", err)
			}
		})
	}
}

func TestNewPiholeProviderTrimsTrailingSlash(t *testing.T) {
	// A trailing slash would produce "/admin/api.php" twice-joined paths like
	// "http://host//admin/api.php".
	p, err := NewPiholeProvider("http://pihole.local/", "tok")
	if err != nil {
		t.Fatalf("NewPiholeProvider() = %v", err)
	}
	if p.baseURL != "http://pihole.local" {
		t.Errorf("baseURL = %q, want the trailing slash removed", p.baseURL)
	}
}

func TestPiholeListRecordsRequestAndConversion(t *testing.T) {
	var gotPath, gotAuth, gotUA string

	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.URL.Query().Get("auth")
		gotUA = r.Header.Get("User-Agent")
		fmt.Fprint(w, `{"data":[
			["web.example.com","100.64.1.1"],
			["web.example.com","fd7a::1"],
			["other.example.org","100.64.1.2"],
			["notexample.com","100.64.1.3"]
		]}`)
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}

	if gotPath != "/admin/api.php" {
		t.Errorf("path = %q, want /admin/api.php", gotPath)
	}
	if gotAuth != "pihole-token-test" {
		t.Errorf("auth = %q, want the API token in the query", gotAuth)
	}
	if gotUA != "dnsscale/1.0" {
		t.Errorf("User-Agent = %q, want dnsscale/1.0", gotUA)
	}

	// The record for a different zone must be excluded.
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2 (other zone filtered out): %+v", len(records), records)
	}
	if records[0].Type != "A" || records[0].Value != "100.64.1.1" {
		t.Errorf("first record = %+v, want an A record", records[0])
	}
	if records[1].Type != "AAAA" {
		t.Errorf("second record = %+v, want an AAAA record", records[1])
	}
	// Pi-hole does not report a TTL; the provider supplies the default.
	if records[0].TTL != 300 {
		t.Errorf("TTL = %d, want the default 300", records[0].TTL)
	}
}

func TestPiholeListRecordsExcludesLookalikeZones(t *testing.T) {
	// Regression: a plain HasSuffix check matched "notexample.com" against the
	// zone "example.com". Deleting records for a zone we do not own is
	// destructive, so the boundary must be explicit.
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[
			["web.example.com","100.64.1.1"],
			["notexample.com","100.64.1.3"],
			["example.com","100.64.1.4"]
		]}`)
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records = %d, want the zone apex and the subdomain only: %+v", len(records), records)
	}
	for _, rec := range records {
		if rec.Name == "notexample.com" {
			t.Errorf("a lookalike zone leaked in: %+v", records)
		}
	}
}

func TestPiholeListRecordsStatusError(t *testing.T) {
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	if _, err := p.ListRecords(context.Background(), "example.com"); err == nil {
		t.Fatal("ListRecords() = nil for a 500, want an error")
	}
}

func TestPiholeListRecordsMalformedResponse(t *testing.T) {
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":`)
	})
	if _, err := p.ListRecords(context.Background(), "example.com"); err == nil {
		t.Fatal("ListRecords() = nil for a truncated response, want an error")
	}
}

func TestPiholeUpdateRecordRejectsUnsupportedType(t *testing.T) {
	// The reconciler writes a TXT ownership record for every node; Pi-hole
	// cannot store it, and the provider must say so rather than silently
	// pretending it worked.
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("UpdateRecord() issued a request for an unsupported record type")
	})

	err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "TXT", Value: `"dnsscale-managed"`,
	})
	if err == nil {
		t.Fatal("UpdateRecord() = nil for a TXT record, want an error")
	}
}

func TestPiholeUpdateRecordDeletesThenAdds(t *testing.T) {
	var posts []url.Values

	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			fmt.Fprint(w, `{"data":[["web.example.com","100.64.1.1"]]}`)
		case http.MethodPost:
			raw, _ := io.ReadAll(r.Body)
			values, _ := url.ParseQuery(string(raw))
			posts = append(posts, values)
			fmt.Fprint(w, `{"status":"success"}`)
		default:
			t.Errorf("unexpected method %s", r.Method)
		}
	})

	err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.9", TTL: 300,
	})
	if err != nil {
		t.Fatalf("UpdateRecord() = %v", err)
	}

	if len(posts) != 2 {
		t.Fatalf("POST count = %d, want delete then add: %+v", len(posts), posts)
	}
	if got := posts[0].Get("customdns"); got != "delete" {
		t.Errorf("first POST customdns = %q, want delete", got)
	}
	if got := posts[1].Get("customdns"); got != "add" {
		t.Errorf("second POST customdns = %q, want add", got)
	}
	if got := posts[1].Get("ip"); got != "100.64.1.9" {
		t.Errorf("add POST ip = %q, want the new address", got)
	}
}

func TestPiholeUpdateRecordSendsAuthInBody(t *testing.T) {
	var gotAuth string

	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			raw, _ := io.ReadAll(r.Body)
			values, _ := url.ParseQuery(string(raw))
			gotAuth = values.Get("auth")
			if ct := r.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
				t.Errorf("Content-Type = %q, want form-urlencoded", ct)
			}
		}
		fmt.Fprint(w, `{"status":"success"}`)
	})

	if err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.9",
	}); err != nil {
		t.Fatalf("UpdateRecord() = %v", err)
	}
	if gotAuth != "pihole-token-test" {
		t.Errorf("auth = %q, want the token in the POST body", gotAuth)
	}
}

func TestPiholeUpdateRecordAPIError(t *testing.T) {
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			fmt.Fprint(w, `{"data":[]}`)
			return
		}
		fmt.Fprint(w, `{"status":"error","error":"cannot change custom dns"}`)
	})

	err := p.UpdateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.9",
	})
	if err == nil {
		t.Fatal("UpdateRecord() = nil for an API error, want an error")
	}
}

func TestPiholeCreateRecordDelegatesToUpdate(t *testing.T) {
	// Pi-hole has no separate create; creating must not invent a second path.
	var sawPost bool

	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			sawPost = true
		}
		fmt.Fprint(w, `{"status":"success"}`)
	})

	if err := p.CreateRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.9",
	}); err != nil {
		t.Fatalf("CreateRecord() = %v", err)
	}
	if !sawPost {
		t.Error("CreateRecord() did not reach the API")
	}
}

func TestPiholeDeleteRecordIgnoresTXT(t *testing.T) {
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("DeleteRecord() issued a request for a TXT record")
	})

	if err := p.DeleteRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "TXT", Value: `"dnsscale-managed"`,
	}); err != nil {
		t.Fatalf("DeleteRecord() = %v, want nil for an unsupported type", err)
	}
}

func TestPiholeDeleteRecordSendsDeleteAction(t *testing.T) {
	var gotAction, gotDomain, gotIP string

	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		values, _ := url.ParseQuery(string(raw))
		gotAction = values.Get("customdns")
		gotDomain = values.Get("domain")
		gotIP = values.Get("ip")
		fmt.Fprint(w, `{"status":"success"}`)
	})

	if err := p.DeleteRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.1",
	}); err != nil {
		t.Fatalf("DeleteRecord() = %v", err)
	}
	if gotAction != "delete" || gotDomain != "web.example.com" || gotIP != "100.64.1.1" {
		t.Errorf("delete request = action:%q domain:%q ip:%q", gotAction, gotDomain, gotIP)
	}
}

func TestPiholeDeleteRecordToleratesMissingRecord(t *testing.T) {
	// Deleting a record that is already gone is success, not an error.
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"error","error":"custom dns not found"}`)
	})

	if err := p.DeleteRecord(context.Background(), "example.com", DNSRecord{
		Name: "gone.example.com", Type: "A", Value: "100.64.1.1",
	}); err != nil {
		t.Fatalf("DeleteRecord() = %v, want nil for a missing record", err)
	}
}

func TestPiholeDeleteRecordPropagatesRealErrors(t *testing.T) {
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"error","error":"session timed out"}`)
	})

	if err := p.DeleteRecord(context.Background(), "example.com", DNSRecord{
		Name: "web.example.com", Type: "A", Value: "100.64.1.1",
	}); err == nil {
		t.Fatal("DeleteRecord() = nil for a real API error, want an error")
	}
}

func TestPiholeUsesRequestContext(t *testing.T) {
	p := newTestPihole(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"data":[]}`)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := p.ListRecords(ctx, "example.com"); err == nil {
		t.Fatal("ListRecords() = nil with a cancelled context, want an error")
	}
}

// Ensure the JSON shapes used above stay decodable by the real types.
func TestPiholeResponseTypesDecode(t *testing.T) {
	var custom PiholeCustomDNSResponse
	if err := json.Unmarshal([]byte(`{"data":[["a.example.com","100.64.1.1"]]}`), &custom); err != nil {
		t.Fatalf("decoding the custom DNS response: %v", err)
	}
	if len(custom.Data) != 1 || custom.Data[0][0] != "a.example.com" {
		t.Errorf("decoded = %+v", custom)
	}

	var api PiholeAPIResponse
	if err := json.Unmarshal([]byte(`{"status":"success"}`), &api); err != nil {
		t.Fatalf("decoding the API response: %v", err)
	}
	if api.Status != "success" {
		t.Errorf("status = %q, want success", api.Status)
	}
}
