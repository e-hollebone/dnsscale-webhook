package providers

// route53_test.go — contract tests for the AWS Route53 provider.
//
// The AWS SDK v2 client is built with BaseEndpoint pointed at a local
// httptest server, so these are real end-to-end SDK calls: the provider builds
// a request, the SDK signs and serialises it to Route53's XML wire format, and
// the fake endpoint answers with genuine Route53 response documents. That
// exercises pagination and XML unmarshalling, not just string handling.

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
)

// Compile-time proof that every provider satisfies the interface the
// reconciler depends on.
var _ DNSProvider = (*Route53Provider)(nil)

const route53NS = "https://route53.amazonaws.com/doc/2013-04-01/"

func newTestRoute53(t *testing.T, handler http.HandlerFunc) *Route53Provider {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider("AKIDTEST", "SECRETTEST", ""),
		),
	)
	if err != nil {
		t.Fatalf("loading the AWS config: %v", err)
	}

	client := route53.NewFromConfig(cfg, func(o *route53.Options) {
		o.BaseEndpoint = &srv.URL
	})

	return &Route53Provider{client: client, zoneID: "Z123456"}
}

const route53ListXML = `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="` + route53NS + `">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>web-server.example.com.</Name>
      <Type>A</Type>
      <TTL>300</TTL>
      <ResourceRecords><ResourceRecord><Value>100.64.1.1</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>web-server.example.com.</Name>
      <Type>AAAA</Type>
      <TTL>300</TTL>
      <ResourceRecords><ResourceRecord><Value>fd7a::1</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
    <ResourceRecordSet>
      <Name>example.com.</Name>
      <Type>MX</Type>
      <TTL>300</TTL>
      <ResourceRecords><ResourceRecord><Value>10 mail.example.com.</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>`

const route53ChangeXML = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="` + route53NS + `">
  <ChangeInfo>
    <Id>/change/C1234567890</Id>
    <Status>PENDING</Status>
    <SubmittedAt>2026-11-10T00:00:00.000Z</SubmittedAt>
  </ChangeInfo>
</ChangeResourceRecordSetsResponse>`

// changeBatch mirrors the request body the SDK serialises.
type changeBatch struct {
	XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	Changes []struct {
		Action            string `xml:"Action"`
		ResourceRecordSet struct {
			Name  string `xml:"Name"`
			Type  string `xml:"Type"`
			TTL   *int64 `xml:"TTL"`
			Value string `xml:"ResourceRecords>ResourceRecord>Value"`
		} `xml:"ResourceRecordSet"`
	} `xml:"ChangeBatch>Changes>Change"`
}

func TestRoute53ListRecords(t *testing.T) {
	var gotPath string

	p := newTestRoute53(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		fmt.Fprint(w, route53ListXML)
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}

	if gotPath != "/2013-04-01/hostedzone/Z123456/rrset" {
		t.Errorf("path = %q, want the hosted zone record set endpoint", gotPath)
	}

	// MX must be dropped: the provider manages A and AAAA only.
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2: %+v", len(records), records)
	}
	if records[0].Type != "A" || records[0].Value != "100.64.1.1" {
		t.Errorf("first record = %+v", records[0])
	}
	if records[0].TTL != 300 {
		t.Errorf("TTL = %d, want 300", records[0].TTL)
	}
	if records[1].Type != "AAAA" || records[1].Value != "fd7a::1" {
		t.Errorf("second record = %+v", records[1])
	}
}

func TestRoute53ListRecordsPaginates(t *testing.T) {
	var requests int

	page1 := `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="` + route53NS + `">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>a.example.com.</Name><Type>A</Type><TTL>300</TTL>
      <ResourceRecords><ResourceRecord><Value>100.64.1.1</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>true</IsTruncated>
  <NextRecordName>b.example.com.</NextRecordName>
  <NextRecordType>A</NextRecordType>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>`

	page2 := `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="` + route53NS + `">
  <ResourceRecordSets>
    <ResourceRecordSet>
      <Name>b.example.com.</Name><Type>A</Type><TTL>300</TTL>
      <ResourceRecords><ResourceRecord><Value>100.64.1.2</Value></ResourceRecord></ResourceRecords>
    </ResourceRecordSet>
  </ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>1</MaxItems>
</ListResourceRecordSetsResponse>`

	p := newTestRoute53(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Query().Get("name") == "b.example.com." {
			fmt.Fprint(w, page2)
			return
		}
		fmt.Fprint(w, page1)
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}
	if requests != 2 {
		t.Errorf("requests = %d, want one per page", requests)
	}
	if len(records) != 2 {
		t.Errorf("records = %d, want both pages: %+v", len(records), records)
	}
}

func TestRoute53ChangeActions(t *testing.T) {
	tests := []struct {
		name string
		call func(p *Route53Provider) error
		want string
	}{
		{"create", func(p *Route53Provider) error {
			return p.CreateRecord(context.Background(), "example.com", DNSRecord{Name: "web.example.com", Type: "A", Value: "100.64.1.1", TTL: 300})
		}, "CREATE"},
		{"update", func(p *Route53Provider) error {
			return p.UpdateRecord(context.Background(), "example.com", DNSRecord{Name: "web.example.com", Type: "A", Value: "100.64.1.1", TTL: 300})
		}, "UPSERT"},
		{"delete", func(p *Route53Provider) error {
			return p.DeleteRecord(context.Background(), "example.com", DNSRecord{Name: "web.example.com", Type: "A", Value: "100.64.1.1", TTL: 300})
		}, "DELETE"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotAction, gotName, gotType, gotValue string
			var gotTTL *int64

			p := newTestRoute53(t, func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				raw, _ := io.ReadAll(r.Body)

				var batch changeBatch
				if err := xml.Unmarshal(raw, &batch); err != nil {
					t.Errorf("decoding the change batch %q: %v", string(raw), err)
				}
				if len(batch.Changes) != 1 {
					t.Errorf("changes = %d, want 1: %s", len(batch.Changes), string(raw))
					fmt.Fprint(w, route53ChangeXML)
					return
				}
				gotAction = batch.Changes[0].Action
				gotName = batch.Changes[0].ResourceRecordSet.Name
				gotType = batch.Changes[0].ResourceRecordSet.Type
				gotValue = batch.Changes[0].ResourceRecordSet.Value
				gotTTL = batch.Changes[0].ResourceRecordSet.TTL

				fmt.Fprint(w, route53ChangeXML)
			})

			if err := tc.call(p); err != nil {
				t.Fatalf("call = %v", err)
			}

			if gotPath != "/2013-04-01/hostedzone/Z123456/rrset/" && gotPath != "/2013-04-01/hostedzone/Z123456/rrset" {
				t.Errorf("path = %q, want the change endpoint", gotPath)
			}
			if gotAction != tc.want {
				t.Errorf("action = %q, want %q", gotAction, tc.want)
			}
			if gotName != "web.example.com" {
				t.Errorf("name = %q, want the record name as the provider built it", gotName)
			}
			if gotType != "A" {
				t.Errorf("type = %q, want A", gotType)
			}
			if gotValue != "100.64.1.1" {
				t.Errorf("value = %q, want the address", gotValue)
			}
			if gotTTL == nil || *gotTTL != 300 {
				t.Errorf("ttl = %v, want 300", gotTTL)
			}
		})
	}
}

func TestRoute53APIError(t *testing.T) {
	p := newTestRoute53(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="`+route53NS+`">
  <Error><Type>Sender</Type><Code>InvalidInput</Code><Message>bad request</Message></Error>
  <RequestId>req-1</RequestId>
</ErrorResponse>`)
	})

	if _, err := p.ListRecords(context.Background(), "example.com"); err == nil {
		t.Fatal("ListRecords() = nil for a 400, want an error")
	}
}

func TestRoute53EmptyZone(t *testing.T) {
	p := newTestRoute53(t, func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="`+route53NS+`">
  <ResourceRecordSets></ResourceRecordSets>
  <IsTruncated>false</IsTruncated>
  <MaxItems>100</MaxItems>
</ListResourceRecordSetsResponse>`)
	})

	records, err := p.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}
	if len(records) != 0 {
		t.Errorf("records = %+v, want none", records)
	}
}

func TestRoute53RequestIsSigned(t *testing.T) {
	// The SDK must sign every request; an unsigned call would fail against the
	// real service and cannot be caught by a fake endpoint that ignores auth.
	var gotAuth string

	p := newTestRoute53(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, route53ListXML)
	})

	if _, err := p.ListRecords(context.Background(), "example.com"); err != nil {
		t.Fatalf("ListRecords() = %v", err)
	}
	if !strings.Contains(gotAuth, "AWS4-HMAC-SHA256") {
		t.Errorf("Authorization = %q, want a SigV4 signature", gotAuth)
	}
	if !strings.Contains(gotAuth, "Credential=AKIDTEST") {
		t.Errorf("Authorization = %q, want the static test credential", gotAuth)
	}
}
