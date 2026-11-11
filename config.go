package main

import (
	"fmt"
	"time"
)

// Config represents the application configuration
type Config struct {
	// Tailscale configuration
	Tailscale TailscaleConfig `mapstructure:"tailscale" yaml:"tailscale"`

	// DNS provider configuration
	DNS DNSConfig `mapstructure:"dns" yaml:"dns"`

	// Application settings
	App AppConfig `mapstructure:"app" yaml:"app"`

	// Logging configuration
	Logging LoggingConfig `mapstructure:"logging" yaml:"logging"`
	// API configuration (self-describing HTTP API)
	API APIConfig `mapstructure:"api" yaml:"api"`
	// Webhook configuration
	Webhook WebhookConfig `mapstructure:"webhook" yaml:"webhook"`
}

// TailscaleConfig holds Tailscale-specific configuration
type TailscaleConfig struct {
	APIKey  string `mapstructure:"api_key" yaml:"api_key"`
	Tailnet string `mapstructure:"tailnet" yaml:"tailnet"`
}

// DNSConfig holds DNS provider configuration
type DNSConfig struct {
	Provider   string           `mapstructure:"provider" yaml:"provider"`
	Domain     string           `mapstructure:"domain" yaml:"domain"`
	ZoneID     string           `mapstructure:"zone_id" yaml:"zone_id,omitempty"`
	Route53    Route53Config    `mapstructure:"route53" yaml:"route53,omitempty"`
	Cloudflare CloudflareConfig `mapstructure:"cloudflare" yaml:"cloudflare,omitempty"`
	Pihole     PiholeConfig     `mapstructure:"pihole" yaml:"pihole,omitempty"`
}

// Route53Config holds AWS Route53 specific configuration
type Route53Config struct {
	// AWS credentials can be provided via environment variables or IAM roles
	// No additional config needed here for now
	Profile string `mapstructure:"profile" yaml:"profile,omitempty"`
	Region  string `mapstructure:"region" yaml:"region,omitempty"`
}

// CloudflareConfig holds Cloudflare specific configuration
type CloudflareConfig struct {
	APIToken string `mapstructure:"api_token" yaml:"api_token"`
}

// PiholeConfig holds Pi-hole specific configuration
type PiholeConfig struct {
	BaseURL  string `mapstructure:"base_url" yaml:"base_url"`
	APIToken string `mapstructure:"api_token" yaml:"api_token"`
}

// AppConfig holds general application configuration
type AppConfig struct {
	Workers      int           `mapstructure:"workers" yaml:"workers"`
	PollInterval time.Duration `mapstructure:"poll_interval" yaml:"poll_interval"`
	RequiredTags []string      `mapstructure:"required_tags" yaml:"required_tags,omitempty"`
}

// LoggingConfig holds logging configuration
type LoggingConfig struct {
	Level  string `mapstructure:"level" yaml:"level"`
	Format string `mapstructure:"format" yaml:"format"` // json or console
}

// APIConfig holds the self-describing HTTP API configuration.
// The API serves the human dashboard, the agent discovery documents and the
// sync trigger; the Tailscale webhook receiver is registered on the same listener.
type APIConfig struct {
	BindAddr string `mapstructure:"bind_addr" yaml:"bind_addr"` // e.g. ":8080", ":443"
	// TLSMode selects how the API serves traffic:
	//   "off"       - plain HTTP, no certificate (default; start without TLS)
	//   "provided"  - HTTPS using the certificate at TLSCert and TLSKey
	//   "tailscale" - HTTPS using a certificate issued by the tailnet
	TLSMode string `mapstructure:"tls_mode" yaml:"tls_mode"`
	TLSCert string `mapstructure:"tls_cert" yaml:"tls_cert"` // certificate file (PEM)
	TLSKey  string `mapstructure:"tls_key" yaml:"tls_key"`   // private key file (PEM)
	// TLSDomain is the domain to request a certificate for in "tailscale" mode.
	// When empty, the entrypoint derives it from the node's tailnet DNS name.
	TLSDomain string `mapstructure:"tls_domain" yaml:"tls_domain"`
	Enabled   bool   `mapstructure:"enabled" yaml:"enabled"`
}

// ServeHTTPS reports whether the API should serve HTTPS for this mode.
func (c APIConfig) ServeHTTPS() bool {
	return c.TLSMode == "provided" || c.TLSMode == "tailscale"
}

// WebhookConfig holds webhook fast-path configuration.
// Tailscale requires webhook endpoints to be HTTPS on port 80 or 443, so set
// api.tls_cert/api.tls_key when webhook.enabled is true.
type WebhookConfig struct {
	Secret  string `mapstructure:"secret" yaml:"secret"` // HMAC secret for Tailscale webhook verification
	Path    string `mapstructure:"path" yaml:"path"`     // default "/api/v1/webhook"
	Enabled bool   `mapstructure:"enabled" yaml:"enabled"`
}

// Validate checks if the configuration is valid
func (c *Config) Validate() error {
	// Validate Tailscale configuration
	if c.Tailscale.APIKey == "" {
		return fmt.Errorf("tailscale.api_key is required")
	}
	if c.Tailscale.Tailnet == "" {
		return fmt.Errorf("tailscale.tailnet is required")
	}

	// Validate DNS configuration
	if c.DNS.Provider == "" {
		return fmt.Errorf("dns.provider is required")
	}
	if c.DNS.Domain == "" {
		return fmt.Errorf("dns.domain is required")
	}

	// Provider-specific validation
	switch c.DNS.Provider {
	case "route53":
		if c.DNS.ZoneID == "" {
			return fmt.Errorf("dns.zone_id is required for route53 provider")
		}
		// Route53 validation - credentials are typically handled via AWS SDK
	case "cloudflare":
		if c.DNS.ZoneID == "" {
			return fmt.Errorf("dns.zone_id is required for cloudflare provider")
		}
		if c.DNS.Cloudflare.APIToken == "" {
			return fmt.Errorf("dns.cloudflare.api_token is required when using cloudflare provider")
		}
	case "pihole":
		if c.DNS.Pihole.BaseURL == "" {
			return fmt.Errorf("dns.pihole.base_url is required when using pihole provider")
		}
		if c.DNS.Pihole.APIToken == "" {
			return fmt.Errorf("dns.pihole.api_token is required when using pihole provider")
		}
	default:
		return fmt.Errorf("unsupported dns provider: %s (supported: route53, cloudflare, pihole)", c.DNS.Provider)
	}

	// Validate app configuration
	if c.App.Workers <= 0 {
		c.App.Workers = 2 // Set default
	}
	if c.App.PollInterval <= 0 {
		c.App.PollInterval = 30 * time.Second // Set default
	}

	// Validate logging configuration
	validLevels := []string{"debug", "info", "warn", "error"}
	levelValid := false
	for _, level := range validLevels {
		if c.Logging.Level == level {
			levelValid = true
			break
		}
	}
	if !levelValid {
		if c.Logging.Level == "" {
			c.Logging.Level = "info" // Set default
		} else {
			return fmt.Errorf("invalid logging level: %s (supported: %v)", c.Logging.Level, validLevels)
		}
	}

	validFormats := []string{"json", "console"}
	formatValid := false
	for _, format := range validFormats {
		if c.Logging.Format == format {
			formatValid = true
			break
		}
	}
	if !formatValid {
		if c.Logging.Format == "" {
			c.Logging.Format = "console" // Set default
		} else {
			return fmt.Errorf("invalid logging format: %s (supported: %v)", c.Logging.Format, validFormats)
		}
	}

	// Validate API configuration
	if c.API.Enabled {
		if c.API.BindAddr == "" {
			c.API.BindAddr = ":8080" // Set default
		}
		switch c.API.TLSMode {
		case "", "off":
			c.API.TLSMode = "off"
		case "provided":
			if c.API.TLSCert == "" || c.API.TLSKey == "" {
				return fmt.Errorf("api.tls_cert and api.tls_key are required when api.tls_mode is \"provided\"")
			}
		case "tailscale":
			if c.API.TLSCert == "" {
				c.API.TLSCert = "/var/lib/tailscale/certs/cert.pem"
			}
			if c.API.TLSKey == "" {
				c.API.TLSKey = "/var/lib/tailscale/certs/key.pem"
			}
		default:
			return fmt.Errorf("invalid api.tls_mode: %s (supported: off, provided, tailscale)", c.API.TLSMode)
		}
	}

	// Validate webhook configuration
	if c.Webhook.Path == "" {
		c.Webhook.Path = "/api/v1/webhook" // Set default
	}
	if c.Webhook.Enabled {
		if !c.API.Enabled {
			return fmt.Errorf("webhook.enabled requires api.enabled to be true")
		}
		if c.Webhook.Secret == "" {
			return fmt.Errorf("webhook.secret is required when webhook is enabled")
		}
	}

	return nil
}
