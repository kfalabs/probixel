package monitor

import (
	"testing"
)

func TestProbeName(t *testing.T) {
	tests := []struct {
		name     string
		probe    Probe
		expected string
	}{
		{"HTTP Probe", &HTTPProbe{}, MonitorTypeHTTP},
		{"TCP Probe", &TCPProbe{}, MonitorTypeTCP},
		{"UDP Probe", &UDPProbe{}, MonitorTypeUDP},
		{"DNS Probe", &DNSProbe{}, MonitorTypeDNS},
		{"Ping Probe", &PingProbe{}, MonitorTypePing},
		{"Host Probe", &HostProbe{}, MonitorTypeHost},
		{"Docker Probe", &DockerProbe{}, MonitorTypeDocker},
		{"WireGuard Probe", &WireguardProbe{}, MonitorTypeWireguard},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.probe.Name(); got != tt.expected {
				t.Errorf("Name() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestSetTargetMode(t *testing.T) {
	tests := []struct {
		name  string
		probe Probe
		mode  string
	}{
		{"HTTP Probe any", &HTTPProbe{}, TargetModeAny},
		{"HTTP Probe all", &HTTPProbe{}, TargetModeAll},
		{"TCP Probe any", &TCPProbe{}, TargetModeAny},
		{"TCP Probe all", &TCPProbe{}, TargetModeAll},
		{"UDP Probe any", &UDPProbe{}, TargetModeAny},
		{"UDP Probe all", &UDPProbe{}, TargetModeAll},
		{"DNS Probe any", &DNSProbe{}, TargetModeAny},
		{"DNS Probe all", &DNSProbe{}, TargetModeAll},
		{"Ping Probe any", &PingProbe{}, TargetModeAny},
		{"Ping Probe all", &PingProbe{}, TargetModeAll},
		{"Host Probe any", &HostProbe{}, TargetModeAny},
		{"Host Probe all", &HostProbe{}, TargetModeAll},
		{"Docker Probe any", &DockerProbe{}, TargetModeAny},
		{"Docker Probe all", &DockerProbe{}, TargetModeAll},
		{"WireGuard Probe any", &WireguardProbe{}, TargetModeAny},
		{"WireGuard Probe all", &WireguardProbe{}, TargetModeAll},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic
			tt.probe.SetTargetMode(tt.mode)
		})
	}
}

func TestGetProbe(t *testing.T) {
	tests := []struct {
		name      string
		probeType string
		wantType  string
		wantErr   bool
	}{
		{"HTTP probe", MonitorTypeHTTP, MonitorTypeHTTP, false},
		{"TCP probe", MonitorTypeTCP, MonitorTypeTCP, false},
		{"UDP probe", MonitorTypeUDP, MonitorTypeUDP, false},
		{"DNS probe", MonitorTypeDNS, MonitorTypeDNS, false},
		{"Ping probe", MonitorTypePing, MonitorTypePing, false},
		{"Host probe", MonitorTypeHost, MonitorTypeHost, false},
		{"Docker probe", MonitorTypeDocker, MonitorTypeDocker, false},
		{"Wireguard probe", MonitorTypeWireguard, MonitorTypeWireguard, false},
		{"Invalid probe", "invalid", "", true},
		{"Empty probe", "", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe, err := GetProbe(tt.probeType)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				}
				if probe != nil {
					t.Error("Expected nil probe on error")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if probe == nil {
				t.Fatal("Expected probe, got nil")
			}

			if probe.Name() != tt.wantType {
				t.Errorf("Got probe type %v, want %v", probe.Name(), tt.wantType)
			}
		})
	}
}
