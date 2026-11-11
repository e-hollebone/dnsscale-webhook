package main

// config_test.go — exhaustive coverage of Config.Validate().
//
// Every branch of the validation switch is exercised, including the defaults
// that Validate() applies in place. The table is deliberately flat so a new
// rule added to Validate() has an obvious place to be tested.

import (
	"strings"
	"testing"
	"time"
)

// validConfig returns a configuration that passes Validate() untouched.
// Tests copy it and break exactly one thing.
func validConfig() *Config {
	return &Config{
		Tailscale: TailscaleConfig{APIKey: "tskey-api-test", Tailnet: "example.ts.net"},
		DNS: DNSConfig{
			Provider:   "cloudflare",
			Domain:     "example.com",
			ZoneID:     "zone-12345",
			Cloudflare: CloudflareConfig{APIToken: "cf-token-test"},
		},
		App:     AppConfig{Workers: 2, PollInterval: 30 * time.Second},
		Logging: LoggingConfig{Level: "info", Format: "console"},
	}
}

// requireErr asserts the error mentions want, so a test cannot pass on an
// unrelated validation failure.
func requireErr(t *testing.T, cfg *Config, want string) {
	t.Helper()
	err := cfg.Validate()
	if err == nil {
		t.Fatalf("Validate() = nil, want an error mentioning %q", want)
	}
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("Validate() = %q, want it to mention %q", err.Error(), want)
	}
}

func requireOK(t *testing.T, cfg *Config) {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate() = %v, want nil", err)
	}
}

func TestValidateRequiredFields(t *testing.T) {
	tests := []struct {
		name string
		mut  func(*Config)
		want string
	}{
		{"tailscale api key", func(c *Config) { c.Tailscale.APIKey = "" }, "tailscale.api_key is required"},
		{"tailscale tailnet", func(c *Config) { c.Tailscale.Tailnet = "" }, "tailscale.tailnet is required"},
		{"dns provider", func(c *Config) { c.DNS.Provider = "" }, "dns.provider is required"},
		{"dns domain", func(c *Config) { c.DNS.Domain = "" }, "dns.domain is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mut(cfg)
			requireErr(t, cfg, tc.want)
		})
	}
}

func TestValidateProviderRules(t *testing.T) {
	tests := []struct {
		name     string
		provider string
		mut      func(*Config)
		want     string
	}{
		{
			"route53 without zone",
			"route53",
			func(c *Config) { c.DNS.ZoneID = "" },
			"dns.zone_id is required for route53 provider",
		},
		{
			"cloudflare without zone",
			"cloudflare",
			func(c *Config) { c.DNS.ZoneID = "" },
			"dns.zone_id is required for cloudflare provider",
		},
		{
			"cloudflare without token",
			"cloudflare",
			func(c *Config) { c.DNS.Cloudflare.APIToken = "" },
			"dns.cloudflare.api_token is required when using cloudflare provider",
		},
		{
			"pihole without base url",
			"pihole",
			func(c *Config) {
				c.DNS.Pihole = PiholeConfig{APIToken: "tok"}
			},
			"dns.pihole.base_url is required when using pihole provider",
		},
		{
			"pihole without token",
			"pihole",
			func(c *Config) {
				c.DNS.Pihole = PiholeConfig{BaseURL: "http://pihole.local"}
			},
			"dns.pihole.api_token is required when using pihole provider",
		},
		{
			"unsupported provider",
			"azure",
			func(c *Config) {},
			"unsupported dns provider: azure (supported: route53, cloudflare, pihole)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.DNS.Provider = tc.provider
			tc.mut(cfg)
			requireErr(t, cfg, tc.want)
		})
	}
}

func TestValidateAppliesDefaults(t *testing.T) {
	t.Run("workers and poll interval", func(t *testing.T) {
		cfg := validConfig()
		cfg.App.Workers = 0
		cfg.App.PollInterval = 0
		requireOK(t, cfg)
		if cfg.App.Workers != 2 {
			t.Errorf("workers = %d, want the default 2", cfg.App.Workers)
		}
		if cfg.App.PollInterval != 30*time.Second {
			t.Errorf("poll interval = %v, want the default 30s", cfg.App.PollInterval)
		}
	})

	t.Run("negative workers and poll interval", func(t *testing.T) {
		cfg := validConfig()
		cfg.App.Workers = -5
		cfg.App.PollInterval = -time.Second
		requireOK(t, cfg)
		if cfg.App.Workers != 2 || cfg.App.PollInterval != 30*time.Second {
			t.Errorf("defaults not applied: workers=%d poll=%v", cfg.App.Workers, cfg.App.PollInterval)
		}
	})

	t.Run("logging level and format", func(t *testing.T) {
		cfg := validConfig()
		cfg.Logging.Level = ""
		cfg.Logging.Format = ""
		requireOK(t, cfg)
		if cfg.Logging.Level != "info" {
			t.Errorf("logging level = %q, want the default %q", cfg.Logging.Level, "info")
		}
		if cfg.Logging.Format != "console" {
			t.Errorf("logging format = %q, want the default %q", cfg.Logging.Format, "console")
		}
	})

	t.Run("api bind address", func(t *testing.T) {
		cfg := validConfig()
		cfg.API = APIConfig{Enabled: true, BindAddr: ""}
		requireOK(t, cfg)
		if cfg.API.BindAddr != ":8080" {
			t.Errorf("bind addr = %q, want the default %q", cfg.API.BindAddr, ":8080")
		}
	})

	t.Run("webhook path", func(t *testing.T) {
		cfg := validConfig()
		cfg.Webhook.Path = ""
		requireOK(t, cfg)
		if cfg.Webhook.Path != "/api/v1/webhook" {
			t.Errorf("webhook path = %q, want the default %q", cfg.Webhook.Path, "/api/v1/webhook")
		}
	})

	t.Run("tls mode empty normalises to off", func(t *testing.T) {
		cfg := validConfig()
		cfg.API = APIConfig{Enabled: true, TLSMode: ""}
		requireOK(t, cfg)
		if cfg.API.TLSMode != "off" {
			t.Errorf("tls mode = %q, want %q", cfg.API.TLSMode, "off")
		}
	})
}

func TestValidateLoggingRules(t *testing.T) {
	tests := []struct {
		name  string
		level string
		want  string
	}{
		{"bogus level", "verbose", "invalid logging level: verbose (supported: [debug info warn error])"},
		{"uppercase level", "INFO", "invalid logging level: INFO (supported: [debug info warn error])"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			cfg.Logging.Level = tc.level
			requireErr(t, cfg, tc.want)
		})
	}

	t.Run("format", func(t *testing.T) {
		cfg := validConfig()
		cfg.Logging.Format = "xml"
		requireErr(t, cfg, "invalid logging format: xml (supported: [json console])")
	})

	t.Run("every documented level is accepted", func(t *testing.T) {
		for _, level := range []string{"debug", "info", "warn", "error"} {
			cfg := validConfig()
			cfg.Logging.Level = level
			requireOK(t, cfg)
		}
	})
}

func TestValidateWebhookRules(t *testing.T) {
	t.Run("webhook requires api", func(t *testing.T) {
		cfg := validConfig()
		cfg.Webhook = WebhookConfig{Enabled: true, Secret: "s"}
		requireErr(t, cfg, "webhook.enabled requires api.enabled to be true")
	})

	t.Run("webhook requires a secret", func(t *testing.T) {
		cfg := validConfig()
		cfg.API = APIConfig{Enabled: true}
		cfg.Webhook = WebhookConfig{Enabled: true, Secret: ""}
		requireErr(t, cfg, "webhook.secret is required when webhook is enabled")
	})

	t.Run("webhook with api and secret is valid", func(t *testing.T) {
		cfg := validConfig()
		cfg.API = APIConfig{Enabled: true}
		cfg.Webhook = WebhookConfig{Enabled: true, Secret: "s"}
		requireOK(t, cfg)
	})

	t.Run("disabled webhook needs neither", func(t *testing.T) {
		cfg := validConfig()
		cfg.API = APIConfig{Enabled: false}
		cfg.Webhook = WebhookConfig{Enabled: false}
		requireOK(t, cfg)
	})
}

func TestValidateAPIOnlyCheckedWhenEnabled(t *testing.T) {
	// An invalid TLS mode must not fail a configuration whose API is off:
	// the operator may keep a template with placeholders in the file.
	cfg := validConfig()
	cfg.API = APIConfig{Enabled: false, TLSMode: "banana"}
	requireOK(t, cfg)
}

func TestValidateTLSDomainAccepted(t *testing.T) {
	// tls_domain is optional and unvalidated; it only matters in tailscale mode.
	cfg := validConfig()
	cfg.API = APIConfig{
		Enabled: true, BindAddr: ":443", TLSMode: "tailscale",
		TLSCert: "/cert.pem", TLSKey: "/key.pem", TLSDomain: "dnsscale.example.com",
	}
	requireOK(t, cfg)
	if cfg.API.TLSDomain != "dnsscale.example.com" {
		t.Errorf("tls domain = %q, want it preserved", cfg.API.TLSDomain)
	}
}
