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

	// Verify optional notifier
	if cfg.Global.Notifier.RateLimit != nil {
		t.Errorf("Expected nil rate limit when notifier section is missing, got %v", *cfg.Global.Notifier.RateLimit)
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
		{"0", 0, false},
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
			"wireguard_threshold_zero",
			`
services:
  - name: "S1"
    type: "wireguard"
    interval: "1m"
    wireguard:
      max_age: "5m"
      restart_threshold: 0
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"restart_threshold cannot be zero",
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
docker-sockets:
  s1: {socket: "/tmp/s1"}
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
			"docker_unknown_socket",
			`
services:
  - name: "S1"
    type: "docker"
    docker: {socket: "unknown"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
    targets: ["c1"]
`,
			"references unknown docker socket",
		},
		{
			name: "docker_socket_invalid",
			content: `
docker-sockets:
  bad:
    protocol: "http"
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "1m"
    monitor_endpoint:
      success:
        url: "http://alert"`,
			wantErr: "docker socket \"bad\" is invalid",
		},
		{
			name: "docker_socket_valid",
			content: `
docker-sockets:
  local:
    socket: "/var/run/docker.sock"
  remote:
    host: "localhost"
    port: 2375
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "1m"
    monitor_endpoint:
      success:
        url: "http://alert"`,
			wantErr: "",
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
			"must have either a root 'tunnel' OR an inline 'wireguard' configuration",
		},
		{
			"wireguard_monitor_missing_maxage",
			`
services:
  - name: "S1"
    type: "wireguard"
    wireguard: {endpoint: "e1", public_key: "pub", private_key: "priv", addresses: "1.1.1.1/32"}
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"wireguard.max_age is mandatory",
		},
		{
			"tunnel_missing_type",
			`
tunnels:
  t1: {wireguard: {endpoint: "e1"}}
services: []
`,
			"tunnel \"t1\" type is mandatory",
		},
		{
			"tunnel_wireguard_missing_fields",
			`
tunnels:
  t1:
    type: "wireguard"
    wireguard: {endpoint: "e1"}
services: []
`,
			"tunnel \"t1\" wireguard requires endpoint, public_key, private_key, and addresses",
		},
		{
			"tunnel_ssh_missing_target",
			`
tunnels:
  t1:
    type: "ssh"
    ssh: {user: "u"}
services: []
`,
			"tunnel \"t1\" of type ssh requires a target",
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
		{
			"rate_limit_empty",
			`
global:
  notifier: {rate_limit: ""}
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"global notifier.rate_limit cannot be an empty string",
		},
		{
			"rate_limit_invalid",
			`
global:
  notifier: {rate_limit: "invalid"}
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"invalid global notifier.rate_limit",
		},
		{
			"ssh_missing_targets",
			`
services:
  - name: "S1"
    type: "ssh"
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"ssh requires at least a 'target' OR a root 'tunnel'",
		},
		{
			"ssh_auth_required_missing_user",
			`
services:
  - name: "S1"
    type: "ssh"
    target: "localhost"
    interval: "1m"
    ssh: {auth_required: true}
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"ssh user is mandatory",
		},
		{
			"ssh_auth_required_missing_pass_key",
			`
services:
  - name: "S1"
    type: "ssh"
    target: "localhost"
    interval: "1m"
    ssh: {auth_required: true, user: "test"}
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"ssh password or private_key is mandatory",
		},
		{
			"ssh_invalid_private_key",
			`
services:
  - name: "S1"
    type: "ssh"
    target: "localhost"
    interval: "1m"
    ssh: {auth_required: true, user: "test", private_key: "invalid-key-data"}
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"ssh private_key is invalid",
		},
		{
			"ssh_auth_not_required_passes",
			`
services:
  - name: "S1"
    type: "ssh"
    target: "localhost"
    interval: "1m"
    ssh: {auth_required: false}
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"",
		},
		{
			"ssh_targets_list_fails",
			`
services:
  - name: "S1"
    type: "ssh"
    targets: ["localhost"]
    interval: "1m"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"must use 'target' (string) instead of 'targets' (list)",
		},
		{
			"http_timeout_exceeds_interval",
			`
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "5s"
    timeout: "10s"
    http: {}
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"service \"S1\" timeout (10s) must be less than interval (5s)",
		},
		{
			"http_default_timeout_exceeds_interval",
			`
services:
  - name: "S1"
    type: "http"
    url: "http://test"
    interval: "1s"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"service \"S1\" timeout (5s) must be less than interval (1s)",
		},
		{
			"ping_timeout_exceeds_interval",
			`
services:
  - name: "S1"
    type: "ping"
    targets: ["1.1.1.1"]
    interval: "2s"
    timeout: "3s"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"service \"S1\" timeout (3s) must be less than interval (2s)",
		},
		{
			"ssh_timeout_exceeds_interval",
			`
services:
  - name: "S1"
    type: "ssh"
    target: "localhost"
    interval: "2s"
    timeout: "3s"
    ssh: {auth_required: false}
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"service \"S1\" timeout (3s) must be less than interval (2s)",
		},
		{
			"docker_default_timeout_exceeds_interval",
			`
docker-sockets:
  s1: {socket: "/tmp/s1"}
services:
  - name: "S1"
    type: "docker"
    docker: {socket: "s1"}
    targets: ["c1"]
    interval: "2s"
    monitor_endpoint: {success: {url: "http://ok"}}
`,
			"service \"S1\" timeout (5s) must be less than interval (2s)",
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
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
				}
			} else {
				if err != nil {
					t.Errorf("expected success, got error: %v", err)
				}
			}
		})
	}
}

func TestTunnelValidation(t *testing.T) {
	validMonitor := MonitorEndpointConfig{
		Success: EndpointConfig{URL: "http://ok"},
	}

	validWG := &WireguardConfig{
		Endpoint:   "1.2.3.4:51820",
		PublicKey:  "pub",
		PrivateKey: "priv",
		Addresses:  "10.0.0.1/24",
		MaxAge:     "5m",
	}

	validSSH := &SSHConfig{
		User:     "user",
		Password: "password",
	}

	tests := []struct {
		name    string
		config  Config
		wantErr bool
		msg     string
	}{
		{
			name: "WireGuard XOR - both tunnel and inline - pass",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"wg-tun": {Type: "wireguard", Wireguard: validWG},
				},
				Services: []Service{
					{
						Name:            "WG Service",
						Type:            "wireguard",
						Interval:        "1m",
						Tunnel:          "wg-tun",
						Wireguard:       &WireguardConfig{MaxAge: "5m"},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "WireGuard XOR - neither tunnel nor inline - fail",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "WG Service",
						Type:            "wireguard",
						Interval:        "1m",
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: true,
			msg:     "must have either a root 'tunnel' OR an inline 'wireguard' configuration",
		},
		{
			name: "WireGuard Monitor - SSH tunnel - fail",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"ssh-tun": {Type: "ssh", SSH: validSSH, Target: "bastion"},
				},
				Services: []Service{
					{
						Name:            "WG Service",
						Type:            "wireguard",
						Interval:        "1m",
						Tunnel:          "ssh-tun",
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: true,
			msg:     "WireGuard monitor cannot use a non-WireGuard tunnel",
		},
		{
			name: "WireGuard Monitor - valid root tunnel - pass",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"wg-tun": {Type: "wireguard", Wireguard: validWG},
				},
				Services: []Service{
					{
						Name:            "WG Service",
						Type:            "wireguard",
						Interval:        "1m",
						Tunnel:          "wg-tun",
						Wireguard:       &WireguardConfig{MaxAge: "5m"}, // Now required
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "WireGuard Monitor - root tunnel missing service max_age - fail",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"wg-tun": {Type: "wireguard", Wireguard: validWG},
				},
				Services: []Service{
					{
						Name:     "WG Service",
						Type:     "wireguard",
						Interval: "1m",
						Tunnel:   "wg-tun",
						// Missing Wireguard.MaxAge override
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: true,
			msg:     "must specify 'wireguard.max_age'",
		},
		{
			name: "SSH Monitor - no tunnel and no target - fail",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "SSH Service",
						Type:            "ssh",
						Interval:        "1m",
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: true,
			msg:     "ssh requires at least a 'target' OR a root 'tunnel'",
		},
		{
			name: "SSH Monitor - root tunnel only - pass",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"ssh-tun": {Type: "ssh", SSH: validSSH, Target: "bastion"},
				},
				Services: []Service{
					{
						Name:            "SSH Service",
						Type:            "ssh",
						Interval:        "1m",
						Tunnel:          "ssh-tun",
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SSH Monitor - target only - pass",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "SSH Service",
						Type:            "ssh",
						Interval:        "1m",
						Target:          "localhost",
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "SSH Monitor - both tunnel and target (bastion) - pass",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"ssh-tun": {Type: "ssh", SSH: validSSH, Target: "bastion"},
				},
				Services: []Service{
					{
						Name:            "SSH Service",
						Type:            "ssh",
						Interval:        "1m",
						Tunnel:          "ssh-tun",
						Target:          "internal.host",
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Docker Monitor - Tunnel with Unix Socket - fail",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"wg-tun": {Type: "wireguard", Wireguard: validWG},
				},
				DockerSockets: map[string]DockerSocketConfig{
					"local": {Socket: "/var/run/docker.sock"},
				},
				Services: []Service{
					{
						Name:            "Docker Service",
						Type:            "docker",
						Interval:        "1m",
						Tunnel:          "wg-tun",
						Docker:          &DockerConfig{Socket: "local"},
						Targets:         []string{"c1"},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: true,
			msg:     "requires a proxied docker socket",
		},
		{
			name: "Docker Monitor - Tunnel with Proxied Socket - pass",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Tunnels: map[string]TunnelConfig{
					"wg-tun": {Type: "wireguard", Wireguard: validWG},
				},
				DockerSockets: map[string]DockerSocketConfig{
					"proxy": {Host: "docker-proxy", Port: 2375},
				},
				Services: []Service{
					{
						Name:            "Docker Service",
						Type:            "docker",
						Interval:        "1m",
						Tunnel:          "wg-tun",
						Docker:          &DockerConfig{Socket: "proxy"},
						Targets:         []string{"c1"},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.msg != "" {
				if err == nil || !strings.Contains(err.Error(), tt.msg) {
					t.Errorf("Validate() error = %v, want message containing %v", err, tt.msg)
				}
			}
		})
	}
}

func TestValidate_TimeoutExceedsInterval(t *testing.T) {
	validMonitor := MonitorEndpointConfig{
		Success: EndpointConfig{URL: "http://ok"},
	}

	tests := []struct {
		name    string
		config  Config
		wantErr string
	}{
		{
			name: "http_timeout_exceeds_interval",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "HTTP Service",
						Type:            "http",
						URL:             "http://test",
						Interval:        "30s",
						Timeout:         "35s",
						HTTP:            &HTTPConfig{},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: "timeout (35s) must be less than interval (30s)",
		},
		{
			name: "tcp_timeout_exceeds_interval",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "TCP Service",
						Type:            "tcp",
						Targets:         []string{"localhost:80"},
						Interval:        "10s",
						Timeout:         "15s",
						TCP:             &TCPConfig{},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: "timeout (15s) must be less than interval (10s)",
		},
		{
			name: "dns_timeout_exceeds_interval",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:     "DNS Service",
						Type:     "dns",
						Targets:  []string{"8.8.8.8"},
						Interval: "5s",
						Timeout:  "10s",
						DNS: &DNSConfig{
							Domain: "example.com",
						},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: "timeout (10s) must be less than interval (5s)",
		},
		{
			name: "tls_timeout_exceeds_interval",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:     "TLS Service",
						Type:     "tls",
						URL:      "https://test",
						Interval: "20s",
						Timeout:  "25s",
						TLS: &TLSConfig{
							CertificateExpiry: "30d",
						},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: "timeout (25s) must be less than interval (20s)",
		},
		{
			name: "udp_timeout_exceeds_interval",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "UDP Service",
						Type:            "udp",
						Targets:         []string{"localhost:53"},
						Interval:        "8s",
						Timeout:         "12s",
						UDP:             &UDPConfig{},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: "timeout (12s) must be less than interval (8s)",
		},
		{
			name: "invalid_timeout_duration",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name:            "HTTP Service",
						Type:            "http",
						URL:             "http://test",
						Interval:        "30s",
						Timeout:         "invalid",
						HTTP:            &HTTPConfig{},
						MonitorEndpoint: validMonitor,
					},
				},
			},
			wantErr: "timeout is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidate_UnknownTunnelType(t *testing.T) {
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"t1": {Type: "unknown-type"},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for unknown tunnel type")
	}
	if !strings.Contains(err.Error(), "unknown tunnel type") {
		t.Errorf("error %q does not mention unknown tunnel type", err.Error())
	}
}

func TestValidate_WireguardUnknownTunnel(t *testing.T) {
	validMonitor := MonitorEndpointConfig{
		Success: EndpointConfig{URL: "http://ok"},
	}
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:            "WG Service",
				Type:            "wireguard",
				Interval:        "1m",
				Tunnel:          "nonexistent-tunnel",
				MonitorEndpoint: validMonitor,
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for unknown tunnel")
	}
	if !strings.Contains(err.Error(), "references unknown tunnel") {
		t.Errorf("error %q does not mention unknown tunnel", err.Error())
	}
}

func TestValidate_ServiceUnknownTunnel(t *testing.T) {
	validMonitor := MonitorEndpointConfig{
		Success: EndpointConfig{URL: "http://ok"},
	}
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:            "HTTP Service",
				Type:            "http",
				URL:             "http://example.com",
				Tunnel:          "missing-tunnel",
				MonitorEndpoint: validMonitor,
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for unknown tunnel")
	}
	if !strings.Contains(err.Error(), "references unknown tunnel \"missing-tunnel\"") {
		t.Errorf("error %q does not mention unknown tunnel \"missing-tunnel\"", err.Error())
	}
}

func TestValidate_WireguardZeroThreshold(t *testing.T) {
	validMonitor := MonitorEndpointConfig{
		Success: EndpointConfig{URL: "http://ok"},
	}
	zero := 0
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:     "WG Service",
				Type:     "wireguard",
				Interval: "1m",
				Wireguard: &WireguardConfig{
					MaxAge:           "5m",
					Endpoint:         "1.2.3.4:51820",
					PublicKey:        "pub",
					PrivateKey:       "priv",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &zero,
				},
				MonitorEndpoint: validMonitor,
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for zero restart_threshold")
	}
	if !strings.Contains(err.Error(), "restart_threshold cannot be zero") {
		t.Errorf("error %q does not mention restart_threshold cannot be zero", err.Error())
	}
}

func TestValidate_TunnelWireguardNegativeThreshold(t *testing.T) {
	negOne := -1
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"wg-tun": {
				Type: "wireguard",
				Wireguard: &WireguardConfig{
					Endpoint:         "1.2.3.4:51820",
					PublicKey:        "pub",
					PrivateKey:       "priv",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &negOne,
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for negative restart_threshold in tunnel")
	}
	if !strings.Contains(err.Error(), "restart_threshold must be positive") {
		t.Errorf("error %q does not mention restart_threshold must be positive", err.Error())
	}
}

func TestValidate_WireguardNegativeThreshold(t *testing.T) {
	validMonitor := MonitorEndpointConfig{
		Success: EndpointConfig{URL: "http://ok"},
	}
	negOne := -1
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:     "WG Service",
				Type:     "wireguard",
				Interval: "1m",
				Wireguard: &WireguardConfig{
					MaxAge:           "5m",
					Endpoint:         "1.2.3.4:51820",
					PublicKey:        "pub",
					PrivateKey:       "priv",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &negOne,
				},
				MonitorEndpoint: validMonitor,
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for negative restart_threshold")
	}
	if !strings.Contains(err.Error(), "restart_threshold must be positive") {
		t.Errorf("error %q does not mention restart_threshold must be positive", err.Error())
	}
}

func TestValidate_TunnelSSHMissingSections(t *testing.T) {
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"ssh-t": {Type: "ssh", Target: "localhost"},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh tunnel without ssh section")
	}
	if !strings.Contains(err.Error(), "requires ssh section") {
		t.Errorf("error %q does not mention requires ssh section", err.Error())
	}
}

func TestValidate_TunnelSSHMissingUser(t *testing.T) {
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"ssh-t": {Type: "ssh", Target: "localhost", SSH: &SSHConfig{}},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh tunnel without user")
	}
	if !strings.Contains(err.Error(), "ssh user is mandatory") {
		t.Errorf("error %q does not mention ssh user is mandatory", err.Error())
	}
}

func TestValidate_TunnelWireguardMissingSection(t *testing.T) {
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"wg-t": {Type: "wireguard"},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for wireguard tunnel without wireguard section")
	}
	if !strings.Contains(err.Error(), "requires wireguard section") {
		t.Errorf("error %q does not mention requires wireguard section", err.Error())
	}
}

func TestValidate_RateLimitEmptyString(t *testing.T) {
	emptyStr := ""
	config := Config{
		Global: GlobalConfig{
			DefaultInterval: "1m",
			Notifier: NotifierConfig{
				RateLimit: &emptyStr,
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for empty rate_limit string")
	}
	if !strings.Contains(err.Error(), "cannot be an empty string") {
		t.Errorf("error %q does not mention cannot be an empty string", err.Error())
	}
}

func TestValidate_RateLimitInvalidDuration(t *testing.T) {
	invalidDur := "invalid"
	config := Config{
		Global: GlobalConfig{
			DefaultInterval: "1m",
			Notifier: NotifierConfig{
				RateLimit: &invalidDur,
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for invalid rate_limit duration")
	}
	if !strings.Contains(err.Error(), "invalid global notifier.rate_limit") {
		t.Errorf("error %q does not mention invalid rate_limit", err.Error())
	}
}

func TestValidate_TunnelSSHMissingTarget(t *testing.T) {
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"ssh-t": {Type: "ssh", SSH: &SSHConfig{User: "test"}},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh tunnel without target")
	}
	if !strings.Contains(err.Error(), "requires a target") {
		t.Errorf("error %q does not mention requires a target", err.Error())
	}
}

func TestValidate_DockerSocketInvalid(t *testing.T) {
	config := Config{
		DockerSockets: map[string]DockerSocketConfig{
			"invalid": {}, // Missing socket path and host/port
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for invalid docker socket")
	}
	if !strings.Contains(err.Error(), "is invalid: must provide") {
		t.Errorf("error %q does not mention is invalid", err.Error())
	}
}

func TestValidate_GlobalDefaultIntervalInvalid(t *testing.T) {
	config := Config{
		Global: GlobalConfig{
			DefaultInterval: "invalid-duration",
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for invalid global default_interval")
	}
	if !strings.Contains(err.Error(), "invalid global default_interval") {
		t.Errorf("error %q does not mention invalid global default_interval", err.Error())
	}
}

func TestValidate_TunnelWireguardMissingFields(t *testing.T) {
	config := Config{
		Tunnels: map[string]TunnelConfig{
			"wg-t": {Type: "wireguard", Wireguard: &WireguardConfig{
				Endpoint: "1.2.3.4:51820",
				// Missing PublicKey, PrivateKey, Addresses
			}},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for wireguard tunnel with missing fields")
	}
	if !strings.Contains(err.Error(), "requires endpoint, public_key, private_key, and addresses") {
		t.Errorf("error %q does not mention required fields", err.Error())
	}
}

func TestValidate_ServiceSSHTargetsUsage(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:    "SSH Service",
				Type:    "ssh",
				Targets: []string{"target1"}, // Should use Target instead
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh service using targets list")
	}
	if !strings.Contains(err.Error(), "must use 'target' (string) instead of 'targets' (list)") {
		t.Errorf("error %q does not mention target usage", err.Error())
	}
}

func TestValidate_ServiceSSHMissingUser(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:   "SSH Service",
				Type:   "ssh",
				Target: "target1",
				SSH:    &SSHConfig{User: ""}, // Missing user
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh service missing user")
	}
	if !strings.Contains(err.Error(), "ssh user is mandatory") {
		t.Errorf("error %q does not mention mandatory user", err.Error())
	}
}

func TestValidate_ServiceSSHMissingAuth(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:   "SSH Service",
				Type:   "ssh",
				Target: "target1",
				SSH:    &SSHConfig{User: "user"}, // Missing password/key
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh service missing auth")
	}
	if !strings.Contains(err.Error(), "password or private_key is mandatory") {
		t.Errorf("error %q does not mention mandatory auth", err.Error())
	}
}

func TestValidate_ServiceSSHInvalidPrivateKey(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:   "SSH Service",
				Type:   "ssh",
				Target: "target1",
				SSH: &SSHConfig{
					User:       "user",
					PrivateKey: "invalid-key",
				},
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for ssh service invalid private key")
	}
	if !strings.Contains(err.Error(), "ssh private_key is invalid") {
		t.Errorf("error %q does not mention invalid private key", err.Error())
	}
}

func TestValidate_ServiceWireguardMismatchedTunnelType(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Tunnels: map[string]TunnelConfig{
			"ssh-tun": {Type: "ssh", Target: "host", SSH: &SSHConfig{User: "root"}},
		},
		Services: []Service{
			{
				Name:   "WG Service",
				Type:   "wireguard",
				Tunnel: "ssh-tun", // Pointing to SSH tunnel instead of WG
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for wireguard service using non-wireguard tunnel")
	}
	if !strings.Contains(err.Error(), "cannot use a non-WireGuard tunnel") {
		t.Errorf("error %q does not mention type mismatch", err.Error())
	}
}

func TestValidate_ServiceWireguardMissingMaxAge(t *testing.T) {
	three := 3
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Tunnels: map[string]TunnelConfig{
			"wg-tun": {
				Type: "wireguard",
				Wireguard: &WireguardConfig{
					Endpoint:         "1.1.1.1:51820",
					PublicKey:        "pub",
					PrivateKey:       "priv",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &three,
				},
			},
		},
		Services: []Service{
			{
				Name:   "WG Service",
				Type:   "wireguard",
				Tunnel: "wg-tun",
				// Missing Wireguard.MaxAge
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for wireguard service missing max_age")
	}
	if !strings.Contains(err.Error(), "must specify 'wireguard.max_age'") {
		t.Errorf("error %q does not mention max_age", err.Error())
	}
}

func TestValidate_ServiceWireguardInlineMissingMaxAge(t *testing.T) {
	three := 3
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name: "WG Service Inline",
				Type: "wireguard",
				Wireguard: &WireguardConfig{
					Endpoint:         "1.1.1.1:51820",
					PublicKey:        "pub",
					PrivateKey:       "priv",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &three,
					// Missing MaxAge
				},
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for inline wireguard service missing max_age")
	}
	if !strings.Contains(err.Error(), "wireguard.max_age is mandatory") {
		t.Errorf("error %q does not mention max_age mandatory", err.Error())
	}
}

func TestValidate_ServiceWireguardNoConfig(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name: "WG Service Empty",
				Type: "wireguard",
				// No Tunnel and no Wireguard inline config
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for wireguard service without config")
	}
	if !strings.Contains(err.Error(), "must have either a root 'tunnel' OR an inline 'wireguard'") {
		t.Errorf("error %q does not mention missing config", err.Error())
	}
}

func TestValidate_ServiceWireguardWithTunnelAndNegativeThreshold(t *testing.T) {
	negOne := -1
	three := 3
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Tunnels: map[string]TunnelConfig{
			"wg-tun": {
				Type: "wireguard",
				Wireguard: &WireguardConfig{
					Endpoint:         "1.1.1.1:51820",
					PublicKey:        "pub",
					PrivateKey:       "priv",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &three,
				},
			},
		},
		Services: []Service{
			{
				Name:   "WG Service",
				Type:   "wireguard",
				Tunnel: "wg-tun",
				Wireguard: &WireguardConfig{
					MaxAge:           "5m",
					RestartThreshold: &negOne, // Invalid override
				},
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for wireguard service with tunnel and negative threshold")
	}
	if !strings.Contains(err.Error(), "restart_threshold must be positive") {
		t.Errorf("error %q does not mention restart_threshold must be positive", err.Error())
	}
}

func TestValidate_ServiceEmptyTimeoutExplicit(t *testing.T) {
	// hit func validateTimeout early return
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:    "HTTP Service",
				Type:    "http",
				URL:     "http://example.com",
				Timeout: "", // Explicit empty
				HTTP:    &HTTPConfig{},
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	if err := config.Validate(); err != nil {
		t.Errorf("unexpected error for explicit empty timeout: %v", err)
	}
}

func TestValidate_UnknownServiceType(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name: "Unknown Service",
				Type: "alien-tech",
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("expected error for unknown service type")
	}
	if !strings.Contains(err.Error(), "unknown type") {
		t.Errorf("error %q does not mention unknown type", err.Error())
	}
}

func TestValidate_ValidTimeouts(t *testing.T) {
	// covers return nil in validateTimeout
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name:     "HTTP Service",
				Type:     "http",
				URL:      "http://example.com",
				Interval: "10s",
				Timeout:  "5s",
				HTTP:     &HTTPConfig{},
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	if err := config.Validate(); err != nil {
		t.Errorf("unexpected error for valid timeout: %v", err)
	}
}

func TestValidate_ServiceHost(t *testing.T) {
	config := Config{
		Global: GlobalConfig{DefaultInterval: "1m"},
		Services: []Service{
			{
				Name: "Host Service",
				Type: "host",
				MonitorEndpoint: MonitorEndpointConfig{
					Success: EndpointConfig{URL: "http://ok"},
				},
			},
		},
	}
	if err := config.Validate(); err != nil {
		t.Errorf("unexpected error for host service: %v", err)
	}
}

func TestValidate_MonitorEndpointTimeouts(t *testing.T) {
	tests := []struct {
		name    string
		config  Config
		wantErr bool
		msg     string
	}{
		{
			name: "Invalid global monitor_endpoint timeout",
			config: Config{
				Global: GlobalConfig{
					DefaultInterval: "1m",
					MonitorEndpoint: GlobalMonitorEndpointConfig{
						Timeout: "invalid",
					},
				},
				Services: []Service{
					{
						Name: "Test",
						Type: "http",
						URL:  "http://test",
						MonitorEndpoint: MonitorEndpointConfig{
							Success: EndpointConfig{URL: "http://ok"},
						},
					},
				},
			},
			wantErr: true,
			msg:     "global monitor_endpoint.timeout is invalid",
		},
		{
			name: "Invalid service monitor_endpoint timeout",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name: "Test",
						Type: "http",
						URL:  "http://test",
						MonitorEndpoint: MonitorEndpointConfig{
							Success: EndpointConfig{URL: "http://ok"},
							Timeout: "invalid",
						},
					},
				},
			},
			wantErr: true,
			msg:     "service \"Test\" monitor_endpoint.timeout is invalid",
		},
		{
			name: "Invalid success endpoint timeout",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name: "Test",
						Type: "http",
						URL:  "http://test",
						MonitorEndpoint: MonitorEndpointConfig{
							Success: EndpointConfig{
								URL:     "http://ok",
								Timeout: "invalid",
							},
						},
					},
				},
			},
			wantErr: true,
			msg:     "service \"Test\" monitor_endpoint.success.timeout is invalid",
		},
		{
			name: "Invalid failure endpoint timeout",
			config: Config{
				Global: GlobalConfig{DefaultInterval: "1m"},
				Services: []Service{
					{
						Name: "Test",
						Type: "http",
						URL:  "http://test",
						MonitorEndpoint: MonitorEndpointConfig{
							Success: EndpointConfig{URL: "http://ok"},
							Failure: &EndpointConfig{
								URL:     "http://fail",
								Timeout: "invalid",
							},
						},
					},
				},
			},
			wantErr: true,
			msg:     "service \"Test\" monitor_endpoint.failure.timeout is invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.msg) {
				t.Errorf("Validate() error = %v, want message containing %v", err, tt.msg)
			}
		})
	}
}
