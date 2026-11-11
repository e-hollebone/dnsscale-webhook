package main

// dashboard_test.go — coverage for the human-facing HTML page.
//
// The page is generated from the same endpoint table that produces the JSON
// index, so these tests assert that coupling: every operation the API exposes
// must appear on the page, and every interpolated value must be escaped.

import (
	"strings"
	"testing"
)

func TestRenderDashboardStructure(t *testing.T) {
	page := renderDashboard("https://dnsscale.example.com")

	for _, want := range []string{
		"DNSScale",
		"https://dnsscale.example.com",
		"Attributes",
		"Functions",
		"Quick Start",
		"Discovery",
		"/health",
		"/api/v1/endpoints",
		"/.well-known/dnsscale",
		"Sync Now",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("dashboard is missing %q", want)
		}
	}
	if !strings.HasPrefix(page, "<!DOCTYPE html>") {
		t.Error("dashboard does not start with a doctype")
	}
	if !strings.Contains(page, "</html>") {
		t.Error("dashboard is not a complete HTML document")
	}
}

func TestRenderDashboardEscapesBaseURL(t *testing.T) {
	// The base URL is reflected into the page and into curl examples. It must
	// be HTML-escaped or a hostile Host header can inject markup.
	page := renderDashboard(`https://x.example.com/"><script>alert(1)</script>`)

	if strings.Contains(page, "<script>alert(1)</script>") {
		t.Error("dashboard reflected an unescaped <script> tag from the base URL")
	}
	if !strings.Contains(page, "&lt;script&gt;") && !strings.Contains(page, "&#34;") {
		t.Error("dashboard did not escape the injected markup")
	}
}

func TestDashboardListsEveryEndpoint(t *testing.T) {
	page := renderDashboard("https://dnsscale.example.com")

	for _, e := range endpoints {
		if !strings.Contains(page, e.Path) {
			t.Errorf("dashboard does not list %s %s", e.Method, e.Path)
		}
		if !strings.Contains(page, e.Description) {
			t.Errorf("dashboard does not describe %s", e.Path)
		}
	}
}

func TestDashboardMarksPostEndpoints(t *testing.T) {
	page := renderDashboard("https://dnsscale.example.com")
	if !strings.Contains(page, `class="method post"`) {
		t.Error("dashboard does not style POST endpoints")
	}
	if !strings.Contains(page, `class="method get"`) {
		t.Error("dashboard does not style GET endpoints")
	}
}

func TestDashboardAttributes(t *testing.T) {
	attrs := dashboardAttributes()

	seen := make(map[string]bool, len(attrs))
	for _, row := range attrs {
		if len(row) != 2 {
			t.Fatalf("attribute row is not a pair: %#v", row)
		}
		if row[0] == "" || row[1] == "" {
			t.Errorf("attribute row has an empty field: %#v", row)
		}
		seen[row[0]] = true
	}

	for _, want := range []string{"Service", "Version", "DNS providers", "Record types", "Poll model"} {
		if !seen[want] {
			t.Errorf("dashboard attributes are missing %q", want)
		}
	}
}

func TestDashboardVersionMatchesService(t *testing.T) {
	page := renderDashboard("https://dnsscale.example.com")
	if !strings.Contains(page, serviceVersion) {
		t.Errorf("dashboard does not report the service version %q", serviceVersion)
	}
}
