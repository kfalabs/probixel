package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	content := `
global:
  default_interval: "1m"
  monitor_endpoint:
    headers:
      User-Agent: "TestAgent/1.0"

services:
  - name: "Test Service"
    type: "http"
    interval: "1m"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
      failure:
        url: "http://alert.test/failure"
      headers:
        X-Custom: "Value"

  - name: "Test Ping Service"
    type: "ping"
    interval: "30s"
    targets:
      - "google.test"
      - "facebook.test"
    target_mode: "any"
    ping: {}
    monitor_endpoint:
      success:
        url: "http://alert.test/ping-success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }() // clean up

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Test loading
	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	// Verify values
	if cfg.Global.MonitorEndpoint.Headers["User-Agent"] != "TestAgent/1.0" {
		t.Errorf("Expected global header User-Agent: TestAgent/1.0, got %s", cfg.Global.MonitorEndpoint.Headers["User-Agent"])
	}

	if len(cfg.Services) != 2 {
		t.Fatalf("Expected 2 services, got %d", len(cfg.Services))
	}

	svc := cfg.Services[0]
	if svc.Name != "Test Service" {
		t.Errorf("Expected service name 'Test Service', got %s", svc.Name)
	}
	if svc.Type != "http" {
		t.Errorf("Expected type http, got %s", svc.Type)
	}
	if svc.URL != "http://example.test" {
		t.Errorf("Expected URL http://example.test, got %s", svc.URL)
	}
	if svc.MonitorEndpoint.Success.URL != "http://alert.test/success" {
		t.Errorf("Expected success URL, got %s", svc.MonitorEndpoint.Success.URL)
	}
	if svc.MonitorEndpoint.Headers["X-Custom"] != "Value" {
		t.Errorf("Expected custom header, got %s", svc.MonitorEndpoint.Headers["X-Custom"])
	}

	pingSvc := cfg.Services[1]
	if pingSvc.Name != "Test Ping Service" {
		t.Errorf("Expected service name 'Test Ping Service', got %s", pingSvc.Name)
	}
	if len(pingSvc.Targets) != 2 {
		t.Errorf("Expected 2 targets for Ping service, got %d", len(pingSvc.Targets))
	}
	if pingSvc.TargetMode != "any" {
		t.Errorf("Expected target mode any, got %s", pingSvc.TargetMode)
	}
	if pingSvc.Targets[0] != "google.test" {
		t.Errorf("Expected target google.test, got %s", pingSvc.Targets[0])
	}
}

func TestParseDuration(t *testing.T) {
	tests := []struct {
		input    string
		expected time.Duration
		wantErr  bool
	}{
		{"60s", 60 * time.Second, false},
		{"1m", 1 * time.Minute, false},
		{"2h", 2 * time.Hour, false},
		{"1d", 24 * time.Hour, false},
		{"2d", 48 * time.Hour, false},
		{"", 0, false},
		{"invalid", 0, true},
		{"1z", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseDuration(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDuration() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.expected {
				t.Errorf("ParseDuration() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/path/config.yaml")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "invalid_config_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte("invalid: yaml: [")); err != nil {
		t.Fatal(err)
	}
	_ = tmpfile.Close()

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_MissingIntervalWithoutGlobalDefault(t *testing.T) {
	content := `
services:
  - name: "S1"
    type: "http"
    url: "http://example.test"
    monitor_endpoint:
      success:
        url: "http://alert.test"
  - name: "S2"
    type: "http"
    url: "http://example2.test"
    monitor_endpoint:
      success:
        url: "http://alert.test"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	// Config should FAIL to load because interval is missing AND no global default
	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected failure when interval is missing and no global default is set")
	}
}

func TestLoadConfig_MissingName(t *testing.T) {
	content := `
global:
  default_interval: "1m"
services:
  - type: "http"
    interval: "1m"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected failure when name is missing")
	}
}

func TestLoadConfig_ServiceIntervalFallback(t *testing.T) {
	content := `
global:
  default_interval: "5m"
services:
  - name: "Fallback Service"
    type: "http"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if len(cfg.Services) != 1 {
		t.Fatalf("Expected 1 service, got %d", len(cfg.Services))
	}

	if cfg.Services[0].Interval != "" {
		t.Errorf("Expected empty service interval, got %s", cfg.Services[0].Interval)
	}
	if cfg.Global.DefaultInterval != "5m" {
		t.Errorf("Expected global default interval '5m', got %s", cfg.Global.DefaultInterval)
	}
}

func TestLoadConfig_TLSMissingExpiry(t *testing.T) {
	content := `
global:
  default_interval: "1m"
services:
  - name: "TLS Missing Expiry"
    type: "tls"
    url: "tls://example.test"
    tls:
      insecure_skip_verify: false
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected failure when certificate_expiry is missing for tls probe")
	}
	if !strings.Contains(err.Error(), "tls.certificate_expiry is mandatory") {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestLoadConfig_WithGlobalDefaultInterval(t *testing.T) {
	content := `
global:
  default_interval: "2m"

services:
  - name: "Test Service"
    type: "http"
    interval: "1m"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.Global.DefaultInterval != "2m" {
		t.Errorf("Expected global default interval '2m', got %s", cfg.Global.DefaultInterval)
	}

	if cfg.Services[0].Interval != "1m" {
		t.Errorf("Expected service interval '1m', got %s", cfg.Services[0].Interval)
	}
}

func TestLoadConfig_HeadersOptional(t *testing.T) {
	content := `
global:
  default_interval: "1m"
services:
  - name: "Test Service"
    type: "http"
    interval: "1m"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig should succeed without headers: %v", err)
	}

	if cfg.Services[0].MonitorEndpoint.Headers != nil {
		t.Errorf("Expected nil headers, got %v", cfg.Services[0].MonitorEndpoint.Headers)
	}

	if cfg.Global.MonitorEndpoint.Headers != nil {
		t.Errorf("Expected nil global headers, got %v", cfg.Global.MonitorEndpoint.Headers)
	}
}
func TestLoadConfig_InvalidGlobalInterval(t *testing.T) {
	content := `
global:
  default_interval: "invalid"
services:
  - name: "Test Service"
    type: "http"
    interval: "1m"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected failure for invalid global default_interval")
	}
}

func TestLoadConfig_InvalidServiceInterval(t *testing.T) {
	content := `
global:
  default_interval: "1m"
services:
  - name: "Test Service"
    type: "http"
    interval: "invalid"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(tmpfile.Name())
	if err == nil {
		t.Error("Expected failure for invalid service interval")
	}
}

func TestLoadConfig_MissingGlobalIntervalWithServiceInterval(t *testing.T) {
	content := `
services:
  - name: "Test Service"
    type: "http"
    interval: "1m"
    url: "http://example.test"
    http:
      method: "GET"
    monitor_endpoint:
      success:
        url: "http://alert.test/success"
`
	tmpfile, err := os.CreateTemp("", "config_test_*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(tmpfile.Name()) }()

	if _, err := tmpfile.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := tmpfile.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = LoadConfig(tmpfile.Name())
	if err != nil {
		t.Fatalf("LoadConfig should succeed when global interval is missing but service interval is present: %v", err)
	}
}
func TestValidate_Errors(t *testing.T) {
	tests := []struct {
		name    string
		content string
		wantErr string
	}{
		{
			"missing_success_url",
			`
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "1m"
    monitor_endpoint:
      success:
        url: ""
`,
			"monitor_endpoint.success.url is mandatory",
		},
		{
			"http_missing_url",
			`
services:
  - name: "S1"
    type: "http"
    interval: "1m"
    monitor_endpoint:
      success: {url: "http://ok"}
`,
			"url is mandatory",
		},
		{
			"tls_missing_section",
			`
services:
  - name: "S1"
    type: "tls"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"requires tls section",
		},
		{
			"tls_missing_url",
			`
services:
  - name: "S1"
    type: "tls"
    tls: {certificate_expiry: "1d"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"url is mandatory",
		},
		{
			"tcp_missing_targets",
			`
services:
  - name: "S1"
    type: "tcp"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"targets is mandatory",
		},
		{
			"dns_missing_targets",
			`
services:
  - name: "S1"
    type: "dns"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"targets is mandatory",
		},
		{
			"ping_missing_targets",
			`
services:
  - name: "S1"
    type: "ping"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"targets is mandatory",
		},
		{
			"docker_missing_section",
			`
services:
  - name: "S1"
    type: "docker"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"requires docker section",
		},
		{
			"docker_missing_socket",
			`
services:
  - name: "S1"
    type: "docker"
    docker: {}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"docker.socket is mandatory",
		},
		{
			"docker_missing_targets",
			`
services:
  - name: "S1"
    type: "docker"
    docker: {socket: "s1"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"targets is mandatory",
		},
		{
			"wireguard_missing_section",
			`
services:
  - name: "S1"
    type: "wireguard"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"requires wireguard section",
		},
		{
			"wireguard_missing_endpoint",
			`
services:
  - name: "S1"
    type: "wireguard"
    wireguard: {}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"wireguard.endpoint is mandatory",
		},
		{
			"wireguard_missing_public_key",
			`
services:
  - name: "S1"
    type: "wireguard"
    wireguard: {endpoint: "e1"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"wireguard.public_key is mandatory",
		},
		{
			"wireguard_missing_private_key",
			`
services:
  - name: "S1"
    type: "wireguard"
    wireguard: {endpoint: "e1", public_key: "pub"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"wireguard.private_key is mandatory",
		},
		{
			"wireguard_missing_addresses",
			`
services:
  - name: "S1"
    type: "wireguard"
    wireguard: {endpoint: "e1", public_key: "pub", private_key: "priv"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"wireguard.addresses is mandatory",
		},
		{
			"wireguard_missing_targets_and_maxage",
			`
services:
  - name: "S1"
    type: "wireguard"
    wireguard: {endpoint: "e1", public_key: "pub", private_key: "priv", addresses: "1.1.1.1/32"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"targets or wireguard.max_age is mandatory",
		},
		{
			"udp_missing_targets",
			`
services:
  - name: "S1"
    type: "udp"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"targets is mandatory",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "config_err_*.yaml")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = os.Remove(tmpfile.Name()) }()
			if _, err := tmpfile.Write([]byte(tt.content)); err != nil {
				t.Fatal(err)
			}
			_ = tmpfile.Close()

			_, err = LoadConfig(tmpfile.Name())
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}
