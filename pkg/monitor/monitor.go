package monitor

import (
	"context"
	"fmt"
	"probixel/pkg/tunnels"
	"time"
)

// Result holds the outcome of a probe check
type Result struct {
	Success          bool
	Duration         time.Duration
	Message          string
	Target           string // The specific target that succeeded (relevant for CSV/list checks)
	Timestamp        time.Time
	SkipNotification bool
	Pending          bool
}

// Tunneler is an optional interface for probes that use tunnels
type Tunneler interface {
	SetTunnel(t tunnels.Tunnel)
}

// Probe is the interface that all monitors must implement
type Probe interface {
	Check(ctx context.Context, target string) (Result, error)
	Name() string
	SetTargetMode(mode string)
	SetTimeout(timeout time.Duration)
}

// Initializer is an optional interface for probes that need setup before the first check
type Initializer interface {
	Initialize() error
}

// MonitorType defines the supported monitor types
const (
	MonitorTypeHTTP      = "http"
	MonitorTypeTCP       = "tcp"
	MonitorTypeDNS       = "dns"
	MonitorTypePing      = "ping"
	MonitorTypeUDP       = "udp"
	MonitorTypeHost      = "host"
	MonitorTypeDocker    = "docker"
	MonitorTypeWireguard = "wireguard"
	MonitorTypeTLS       = "tls"
	MonitorTypeSSH       = "ssh"
)

// TargetMode defines how multiple targets are evaluated
const (
	TargetModeAny = "any" // Success if any target succeeds (default)
	TargetModeAll = "all" // Success only if all targets succeed
)

// Factory returns a Probe based on the type
func GetProbe(monitorType string) (Probe, error) {
	switch monitorType {
	case MonitorTypeHTTP:
		return &HTTPProbe{}, nil
	case MonitorTypeTCP:
		return &TCPProbe{}, nil
	case MonitorTypeDNS:
		return &DNSProbe{}, nil
	case MonitorTypePing:
		return &PingProbe{}, nil
	case MonitorTypeUDP:
		return &UDPProbe{}, nil
	case MonitorTypeHost:
		return &HostProbe{}, nil
	case MonitorTypeDocker:
		return &DockerProbe{}, nil
	case MonitorTypeWireguard:
		return &WireguardProbe{}, nil
	case MonitorTypeTLS:
		return &TLSProbe{}, nil
	case MonitorTypeSSH:
		return &SSHProbe{}, nil
	default:
		return nil, fmt.Errorf("unknown monitor type: %s", monitorType)
	}
}
