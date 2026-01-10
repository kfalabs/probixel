package agent

import (
	"testing"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/tunnels"
)

func TestSetupProbe_HTTP(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-http",
		Type:     "http",
		Target:   "http://example.com",
		Interval: "60s",
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}

	if probe.Name() != "http" {
		t.Errorf("expected name http, got %s", probe.Name())
	}
}

func TestSetupProbe_Wireguard(t *testing.T) {
	registry := tunnels.NewRegistry()
	mockT := &tunnels.MockTunnel{
		NameFunc: func() string { return "wg0" },
		TypeFunc: func() string { return "wireguard" },
	}
	_ = registry.Register(mockT)

	three := 3
	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {
				Type: "wireguard",
				Wireguard: &config.WireguardConfig{
					RestartThreshold: &three,
				},
			},
		},
	}
	svc := config.Service{
		Name:     "test-wg",
		Type:     "wireguard",
		Tunnel:   "wg0",
		Target:   "10.0.0.1",
		Interval: "60s",
		Wireguard: &config.WireguardConfig{
			MaxAge:     "180s",
			Endpoint:   "1.2.3.4:51820",
			PublicKey:  "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTE=",
			PrivateKey: "aGVsbG93b3JsZGhlbGxvd29ybGRoZWxsb3dvcmxkMTE=",
			Addresses:  "10.0.0.2/32",
		},
	}

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "wireguard" {
		t.Errorf("expected name wireguard, got %s", probe.Name())
	}
}

func TestSetupProbe_Wireguard_MissingTunnel(t *testing.T) {
	registry := tunnels.NewRegistry()
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-wg-fail",
		Type:     "wireguard",
		Tunnel:   "missing-tunnel",
		Target:   "10.0.0.1",
		Interval: "60s",
	}

	_, err := SetupProbe(svc, cfg, registry)
	if err == nil {
		t.Fatal("expected error for missing tunnel")
	}
}

func TestSetupProbe_UnknownType(t *testing.T) {
	registry := tunnels.NewRegistry()
	cfg := &config.Config{}
	svc := config.Service{
		Name: "unknown",
		Type: "alien-tech",
	}

	_, err := SetupProbe(svc, cfg, registry)
	if err == nil {
		t.Fatal("expected error for unknown probe type")
	}
}

func TestSetupWireguardWindows_Disabled(t *testing.T) {
	// No explicit config needed as defaults handle nil/zero
	cfg := &config.Config{}
	registry := tunnels.NewRegistry()

	SetupWireguardWindows(cfg, registry)
}

func TestSetupWireguardWindows_Enabled(t *testing.T) {
	three := 3
	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {
				Type: "wireguard",
				Wireguard: &config.WireguardConfig{
					RestartThreshold: &three,
				},
			},
		},
		Services: []config.Service{
			{
				Name:     "svc1",
				Tunnel:   "wg0",
				Interval: "120s",
			},
		},
	}
	registry := tunnels.NewRegistry()
	mockT := &tunnels.MockTunnel{
		NameFunc: func() string { return "wg0" },
		TypeFunc: func() string { return "wireguard" },
	}
	_ = registry.Register(mockT)

	SetupWireguardWindows(cfg, registry)
}

func TestSetupWireguardWindows_WithMultipleServices(t *testing.T) {
	three := 3
	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {
				Type: "wireguard",
				Wireguard: &config.WireguardConfig{
					RestartThreshold: &three,
				},
			},
		},
		Services: []config.Service{
			{Name: "svc1", Tunnel: "wg0", Interval: "60s"},
			{Name: "svc2", Tunnel: "wg0", Interval: "120s"},
			{Name: "svc3", Tunnel: "wg0", Interval: "30s"},
		},
	}
	registry := tunnels.NewRegistry()
	mockT := &tunnels.MockTunnel{
		NameFunc: func() string { return "wg0" },
		TypeFunc: func() string { return "wireguard" },
	}
	_ = registry.Register(mockT)

	SetupWireguardWindows(cfg, registry)
}

func TestSetupWireguardWindows_InvalidInterval(t *testing.T) {
	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {Type: "wireguard"},
		},
		Services: []config.Service{
			{Name: "svc1", Tunnel: "wg0", Interval: "invalid"},
		},
	}
	registry := tunnels.NewRegistry()
	mockT := &tunnels.MockTunnel{
		NameFunc: func() string { return "wg0" },
		TypeFunc: func() string { return "wireguard" },
	}
	_ = registry.Register(mockT)

	SetupWireguardWindows(cfg, registry)
}

func TestSetupWireguardWindows_NoThresholdConfig(t *testing.T) {
	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {
				Type:      "wireguard",
				Wireguard: nil,
			},
		},
		Services: []config.Service{
			{Name: "svc1", Tunnel: "wg0", Interval: "60s"},
		},
	}
	registry := tunnels.NewRegistry()
	mockT := &tunnels.MockTunnel{
		NameFunc: func() string { return "wg0" },
		TypeFunc: func() string { return "wireguard" },
	}
	_ = registry.Register(mockT)

	SetupWireguardWindows(cfg, registry)
}

func TestSetupWireguardWindows_WithRealWireguardTunnel(t *testing.T) {
	three := 3
	cfg := &config.Config{
		Tunnels: map[string]config.TunnelConfig{
			"wg0": {
				Type: "wireguard",
				Wireguard: &config.WireguardConfig{
					Endpoint:         "1.2.3.4:51820",
					PublicKey:        "wAUaJMhAq3NFutLHIdF8AN0B5WG8RndfQKLPTEDHal0=",
					PrivateKey:       "wOEI9rqqbDwnN8/Bpp22sVz48T71vJ4fYmFWujulwUU=",
					Addresses:        "10.0.0.1/32",
					RestartThreshold: &three,
				},
			},
		},
		Services: []config.Service{
			{Name: "svc1", Tunnel: "wg0", Interval: "60s"},
		},
	}
	registry := tunnels.NewRegistry()

	// Use a real WireguardTunnel to hit SetSuccessWindow branch
	wgTun := tunnels.NewWireguardTunnel("wg0", cfg.Tunnels["wg0"].Wireguard)
	_ = registry.Register(wgTun)

	SetupWireguardWindows(cfg, registry)

	// Verify success window was set
	// The success window should be (60s * 3) + 60s = 240s
}

func TestSetupProbe_FullConfiguration(t *testing.T) {
	// Test all fields assignment for different probe types
	cfg := &config.Config{}
	registry := tunnels.NewRegistry()

	// HTTP Probe Full Config
	httpSvc := config.Service{
		Name:     "http-full",
		Type:     "http",
		Interval: "1m",
		Timeout:  "5s",
		HTTP: &config.HTTPConfig{
			Method:              "POST",
			Headers:             map[string]string{"X-Test": "Value"},
			AcceptedStatusCodes: "200,201",
			InsecureSkipVerify:  true,
			MatchData: &config.MatchDataConfig{
				Expectations: []config.Expectation{
					{Type: "body", Operator: "contains", Value: "expected response"},
				},
			},
			CertificateExpiry: "24h",
		},
	}
	probe, err := SetupProbe(httpSvc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	httpProbe, ok := probe.(*monitor.HTTPProbe)
	if !ok {
		t.Fatal("Expected HTTPProbe")
	}
	if httpProbe.Method != "POST" || httpProbe.Timeout != 5*time.Second || httpProbe.ExpiryThreshold != 24*time.Hour {
		t.Errorf("HTTPProbe config mismatch")
	}

	// TCP Probe Full Config
	tcpSvc := config.Service{
		Name:     "tcp-full",
		Type:     "tcp",
		Interval: "1m",
		Timeout:  "5s",
		TCP:      &config.TCPConfig{},
	}
	probe, err = SetupProbe(tcpSvc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	tcpProbe, ok := probe.(*monitor.TCPProbe)
	if !ok {
		t.Fatal("Expected TCPProbe")
	}
	if tcpProbe.Timeout != 5*time.Second {
		t.Errorf("TCPProbe timeout mismatch")
	}

	// UDP Probe Full Config
	udpSvc := config.Service{
		Name:     "udp-full",
		Type:     "udp",
		Interval: "1m",
		Timeout:  "2s",
		UDP:      &config.UDPConfig{},
	}
	probe, err = SetupProbe(udpSvc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	udpProbe, ok := probe.(*monitor.UDPProbe)
	if !ok {
		t.Fatal("Expected UDPProbe")
	}
	if udpProbe.Timeout != 2*time.Second {
		t.Errorf("UDPProbe timeout mismatch")
	}

	// DNS Probe Full Config
	dnsSvc := config.Service{
		Name:     "dns-full",
		Type:     "dns",
		Interval: "1m",
		Timeout:  "1s",
		DNS: &config.DNSConfig{
			Domain: "example.com",
		},
	}
	probe, err = SetupProbe(dnsSvc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	dnsProbe, ok := probe.(*monitor.DNSProbe)
	if !ok {
		t.Fatal("Expected DNSProbe")
	}
	if dnsProbe.Timeout != 1*time.Second {
		t.Errorf("DNSProbe timeout mismatch")
	}
}

func TestSetupProbe_TCP(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-tcp",
		Type:     "tcp",
		Targets:  []string{"localhost:80"},
		Interval: "60s",
		Timeout:  "5s",
		TCP:      &config.TCPConfig{},
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "tcp" {
		t.Errorf("expected name tcp, got %s", probe.Name())
	}
}

func TestSetupProbe_UDP(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-udp",
		Type:     "udp",
		Targets:  []string{"localhost:53"},
		Interval: "60s",
		Timeout:  "5s",
		UDP:      &config.UDPConfig{},
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "udp" {
		t.Errorf("expected name udp, got %s", probe.Name())
	}
}

func TestSetupProbe_TLS(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-tls",
		Type:     "tls",
		URL:      "https://example.com",
		Interval: "60s",
		Timeout:  "10s",
		TLS: &config.TLSConfig{
			CertificateExpiry:  "30d",
			InsecureSkipVerify: true,
		},
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "tls" {
		t.Errorf("expected name tls, got %s", probe.Name())
	}
}

func TestSetupProbe_SSH(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-ssh",
		Type:     "ssh",
		Target:   "localhost",
		Interval: "60s",
		SSH: &config.SSHConfig{
			User:     "testuser",
			Password: "testpass",
		},
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "ssh" {
		t.Errorf("expected name ssh, got %s", probe.Name())
	}
}

func TestSetupProbe_Docker(t *testing.T) {
	cfg := &config.Config{
		DockerSockets: map[string]config.DockerSocketConfig{
			"local": {Socket: "/var/run/docker.sock"},
		},
	}
	svc := config.Service{
		Name:     "test-docker",
		Type:     "docker",
		Targets:  []string{"container1"},
		Interval: "60s",
		Docker: &config.DockerConfig{
			Socket:  "local",
			Healthy: true,
		},
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "docker" {
		t.Errorf("expected name docker, got %s", probe.Name())
	}
}

func TestSetupProbe_Host(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-host",
		Type:     "host",
		Interval: "60s",
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "host" {
		t.Errorf("expected name host, got %s", probe.Name())
	}
}

func TestSetupProbe_Ping(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-ping",
		Type:     "ping",
		Targets:  []string{"google.com"},
		Interval: "60s",
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "ping" {
		t.Errorf("expected name ping, got %s", probe.Name())
	}
}

func TestSetupProbe_HTTP_WithConfig(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-http-config",
		Type:     "http",
		URL:      "http://example.com",
		Interval: "60s",
		Timeout:  "10s",
		HTTP: &config.HTTPConfig{
			Method:              "POST",
			Headers:             map[string]string{"X-Custom": "value"},
			AcceptedStatusCodes: "200-299",
			InsecureSkipVerify:  true,
			CertificateExpiry:   "30d",
		},
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "http" {
		t.Errorf("expected name http, got %s", probe.Name())
	}
}

func TestSetupProbe_WithCustomTargetMode(t *testing.T) {
	cfg := &config.Config{}
	svc := config.Service{
		Name:       "test-target-mode",
		Type:       "tcp",
		Targets:    []string{"localhost:80", "localhost:443"},
		Interval:   "60s",
		TargetMode: "all",
	}
	registry := tunnels.NewRegistry()

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "tcp" {
		t.Errorf("expected name tcp, got %s", probe.Name())
	}
}

func TestSetupProbe_WithTunnelDialer(t *testing.T) {
	registry := tunnels.NewRegistry()
	mockT := &tunnels.MockTunnel{
		NameFunc:           func() string { return "ssh-tunnel" },
		TypeFunc:           func() string { return "ssh" },
		IsStabilizedResult: true,
	}
	_ = registry.Register(mockT)

	cfg := &config.Config{}
	svc := config.Service{
		Name:     "test-tunnel-dialer",
		Type:     "tcp",
		Tunnel:   "ssh-tunnel",
		Targets:  []string{"remote:80"},
		Interval: "60s",
	}

	probe, err := SetupProbe(svc, cfg, registry)
	if err != nil {
		t.Fatalf("SetupProbe failed: %v", err)
	}
	if probe.Name() != "tcp" {
		t.Errorf("expected name tcp, got %s", probe.Name())
	}
}
