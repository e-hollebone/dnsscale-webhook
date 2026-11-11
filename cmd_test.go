package main

// cmd_test.go — coverage for the CLI surface: flag registration, the
// flag/env/config binding, and the generated example configuration.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// boundFlags lists every flag the root command must expose. A flag that is
// registered but never bound to viper is a silent configuration bug, so the
// test asserts both halves.
var boundFlags = []struct {
	flag  string
	key   string
	env   string
	probe string
}{
	{"tailscale-api-key", "tailscale.api_key", "TAILSCALE_API_KEY", "probe"},
	{"tailscale-tailnet", "tailscale.tailnet", "TAILSCALE_TAILNET", "probe"},
	{"dns-provider", "dns.provider", "", "probe"},
	{"dns-domain", "dns.domain", "DNS_DOMAIN", "probe"},
	{"dns-zone-id", "dns.zone_id", "DNS_ZONE_ID", "probe"},
	{"cloudflare-api-token", "dns.cloudflare.api_token", "CLOUDFLARE_API_TOKEN", "probe"},
	{"route53-profile", "dns.route53.profile", "AWS_PROFILE", "probe"},
	{"route53-region", "dns.route53.region", "AWS_REGION", "probe"},
	{"pihole-base-url", "dns.pihole.base_url", "PIHOLE_BASE_URL", "probe"},
	{"pihole-api-token", "dns.pihole.api_token", "PIHOLE_API_TOKEN", "probe"},
	{"workers", "app.workers", "", "7"},
	{"poll-interval", "app.poll_interval", "", "5s"},
	{"required-tags", "app.required_tags", "", "probe-tag"},
	{"log-level", "logging.level", "", "probe"},
	{"log-format", "logging.format", "", "probe"},
	{"api-bind-addr", "api.bind_addr", "API_BIND_ADDR", "probe"},
	{"api-tls-mode", "api.tls_mode", "API_TLS_MODE", "probe"},
	{"api-tls-cert", "api.tls_cert", "API_TLS_CERT", "probe"},
	{"api-tls-key", "api.tls_key", "API_TLS_KEY", "probe"},
	{"api-tls-domain", "api.tls_domain", "API_TLS_DOMAIN", "probe"},
	{"api-enabled", "api.enabled", "API_ENABLED", "true"},
	{"webhook-path", "webhook.path", "WEBHOOK_PATH", "probe"},
	{"webhook-enabled", "webhook.enabled", "WEBHOOK_ENABLED", "true"},
}

func TestEveryFlagIsRegistered(t *testing.T) {
	for _, f := range boundFlags {
		t.Run(f.flag, func(t *testing.T) {
			if rootCmd.PersistentFlags().Lookup(f.flag) == nil {
				t.Errorf("flag --%s is not registered", f.flag)
			}
		})
	}
}

func TestFlagsAreBoundToViper(t *testing.T) {
	// Viper only consults a bound pflag once the flag has been changed, so
	// "IsSet" is not a valid probe for binding. Setting the flag and reading
	// the key back is.
	for _, f := range boundFlags {
		t.Run(f.key, func(t *testing.T) {
			flags := rootCmd.PersistentFlags()
			flag := flags.Lookup(f.flag)
			if flag == nil {
				t.Fatalf("flag --%s is not registered", f.flag)
			}

			if err := flags.Set(f.flag, f.probe); err != nil {
				t.Fatalf("setting --%s: %v", f.flag, err)
			}
			// Restore both the value and the Changed marker: a changed flag
			// outranks the environment in viper's precedence, and leaving it
			// set would leak into every later test.
			defer func() {
				flags.Set(f.flag, flag.DefValue)
				flag.Changed = false
			}()

			if got := viper.Get(f.key); got == nil {
				t.Errorf("viper does not read %q from --%s after the flag changed", f.key, f.flag)
			}
		})
	}
}

func TestEnvironmentOverridesDefaults(t *testing.T) {
	// Viper's precedence puts a set environment variable above an unchanged
	// flag default. This is what lets the container configure the API without
	// a config file.
	t.Setenv("API_TLS_MODE", "tailscale")
	t.Setenv("API_TLS_DOMAIN", "dnsscale.example.com")
	t.Setenv("WEBHOOK_ENABLED", "true")

	if got := viper.GetString("api.tls_mode"); got != "tailscale" {
		t.Errorf("api.tls_mode = %q, want tailscale from the environment", got)
	}
	if got := viper.GetString("api.tls_domain"); got != "dnsscale.example.com" {
		t.Errorf("api.tls_domain = %q, want the environment value", got)
	}
	if !viper.GetBool("webhook.enabled") {
		t.Error("webhook.enabled = false, want true from the environment")
	}
}

func TestWebhookSecretHasNoFlag(t *testing.T) {
	// The secret must never be passable on the command line, where it would
	// be visible in a process listing.
	if rootCmd.PersistentFlags().Lookup("webhook-secret") != nil {
		t.Fatal("--webhook-secret exists; the secret must come from the config file or WEBHOOK_SECRET")
	}
}

func TestGenerateExampleConfig(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "nested", "dnsscale.example.yaml")

	if err := generateExampleConfig(out); err != nil {
		t.Fatalf("generateExampleConfig() = %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("reading the generated config: %v", err)
	}

	// Read the file back through the same loader the daemon uses, so the
	// template is verified as a configuration and not just as text.
	v := viper.New()
	v.SetConfigFile(out)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("the generated config cannot be parsed: %v\n%s", err, raw)
	}

	for _, section := range []string{"tailscale", "dns", "app", "logging", "api", "webhook"} {
		if !v.IsSet(section) {
			t.Errorf("generated config is missing the %q section", section)
		}
	}
	if got := v.GetString("api.tls_mode"); got != "off" {
		t.Errorf("api.tls_mode = %q, want the default %q", got, "off")
	}
	if !v.GetBool("api.enabled") {
		t.Error("api.enabled = false, want true")
	}
	if v.GetString("api.bind_addr") == "" {
		t.Error("api.bind_addr is empty, want a listen address")
	}
	if v.GetString("webhook.path") != "/api/v1/webhook" {
		t.Errorf("webhook.path = %q, want /api/v1/webhook", v.GetString("webhook.path"))
	}

	// The documented example must not carry a real credential.
	body := string(raw)
	for _, secret := range []string{
		"tskey-api-PLACEHOLDER",
		"tskey-webhook-PLACEHOLDER",
		"zone-id-PLACEHOLDER",
		"ip-PLACEHOLDER",
		"domain-PLACEHOLDER",
	} {
		if strings.Contains(body, secret) {
			t.Errorf("generated config contains a real internal value: %s", secret)
		}
	}
}

func TestGeneratedExampleConfigIsValid(t *testing.T) {
	// Round-trip: the file the CLI writes must pass the same validation the
	// daemon applies, once the placeholder credentials are filled in.
	dir := t.TempDir()
	out := filepath.Join(dir, "example.yaml")
	if err := generateExampleConfig(out); err != nil {
		t.Fatalf("generateExampleConfig() = %v", err)
	}

	v := viper.New()
	v.SetConfigFile(out)
	if err := v.ReadInConfig(); err != nil {
		t.Fatalf("reading the generated config: %v", err)
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		t.Fatalf("unmarshalling the generated config: %v", err)
	}

	// Fill the placeholders the template leaves behind.
	cfg.Tailscale.APIKey = "tskey-api-placeholder"
	cfg.DNS.Cloudflare.APIToken = "cf-token-placeholder"
	cfg.Logging.Level = "info"
	cfg.Logging.Format = "console"

	if err := cfg.Validate(); err != nil {
		t.Errorf("the generated config does not validate: %v", err)
	}
}

func TestGenerateExampleConfigRejectsBadPath(t *testing.T) {
	// An uncreatable path must produce an error, not a panic.
	if err := generateExampleConfig(string([]byte{0})); err == nil {
		t.Error("generateExampleConfig() = nil for an invalid path, want an error")
	}
}
