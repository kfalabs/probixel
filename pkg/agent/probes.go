package agent

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/monitor"
	"probixel/pkg/tunnels"
)

func SetupWireguardWindows(cfg *config.Config, registry *tunnels.Registry) {
	tunnelMaxIntervals := make(map[string]time.Duration)
	for _, svc := range cfg.Services {
		if svc.Tunnel != "" {
			interval, err := config.ParseDuration(svc.Interval)
			if err != nil {
				continue
			}
			if existing, ok := tunnelMaxIntervals[svc.Tunnel]; !ok || interval > existing {
				tunnelMaxIntervals[svc.Tunnel] = interval
			}
		}
	}

	for tunnelName, maxInterval := range tunnelMaxIntervals {
		if t, ok := registry.Get(tunnelName); ok {
			if wgTun, ok := t.(*tunnels.WireguardTunnel); ok {
				threshold := 1
				if tCfg, ok := cfg.Tunnels[tunnelName]; ok && tCfg.Wireguard != nil && tCfg.Wireguard.RestartThreshold != nil {
					threshold = *tCfg.Wireguard.RestartThreshold
				}
				successWindow := (maxInterval * time.Duration(threshold)) + 60*time.Second
				wgTun.SetSuccessWindow(successWindow)
				log.Printf("[Tunnel:%s] Set success window to %v (max interval %v * threshold %d + 60s grace)", tunnelName, successWindow, maxInterval, threshold)
			}
		}
	}
}

func SetupProbe(svc config.Service, cfg *config.Config, registry *tunnels.Registry) (monitor.Probe, error) {
	probe, err := monitor.GetProbe(svc.Type)
	if err != nil {
		return nil, err
	}

	switch p := probe.(type) {
	case *monitor.HTTPProbe:
		if svc.HTTP != nil {
			p.Method = svc.HTTP.Method
			p.Headers = svc.HTTP.Headers
			p.AcceptedStatusCodes = svc.HTTP.AcceptedStatusCodes
			p.InsecureSkipVerify = svc.HTTP.InsecureSkipVerify
			p.MatchData = svc.HTTP.MatchData
			if svc.HTTP.CertificateExpiry != "" {
				if d, err := config.ParseDuration(svc.HTTP.CertificateExpiry); err == nil {
					p.ExpiryThreshold = d
				}
			}
		}
		if p.Method == "" {
			p.Method = "GET"
		}
	case *monitor.DNSProbe:
		if svc.DNS != nil {
			p.SetDomain(svc.DNS.Domain)
		}
	case *monitor.SSHProbe:
		if svc.SSH != nil {
			p.Config = svc.SSH
		}
	case *monitor.WireguardProbe:
		if svc.Wireguard != nil {
			p.Config = svc.Wireguard
		}
	}

	if tlsProbe, ok := probe.(*monitor.TLSProbe); ok && svc.TLS != nil {
		if svc.TLS.CertificateExpiry != "" {
			if dur, err := config.ParseDuration(svc.TLS.CertificateExpiry); err == nil {
				tlsProbe.ExpiryThreshold = dur
			}
		}
		tlsProbe.InsecureSkipVerify = svc.TLS.InsecureSkipVerify
	}

	if dockerProbe, ok := probe.(*monitor.DockerProbe); ok && svc.Docker != nil {
		dockerProbe.Sockets = cfg.DockerSockets
		dockerProbe.SocketName = svc.Docker.Socket
		dockerProbe.Healthy = svc.Docker.Healthy
	}

	// Set universal timeout
	timeoutStr := svc.Timeout
	if timeoutStr == "" {
		timeoutStr = "5s"
	}
	if d, err := config.ParseDuration(timeoutStr); err == nil {
		probe.SetTimeout(d)
	}

	if svc.Tunnel != "" {
		if t, ok := registry.Get(svc.Tunnel); ok {
			dialer := func(ctx context.Context, network, address string) (net.Conn, error) {
				conn, err := t.DialContext(ctx, network, address)
				if err != nil {
					if t.IsStabilized() {
						t.ReportFailure()
					}
				}
				return conn, err
			}

			switch p := probe.(type) {
			case *monitor.HTTPProbe:
				p.DialContext = dialer
			case *monitor.TCPProbe:
				p.DialContext = dialer
			case *monitor.PingProbe:
				p.DialContext = dialer
			case *monitor.DNSProbe:
				p.DialContext = dialer
			case *monitor.UDPProbe:
				p.DialContext = dialer
			case *monitor.TLSProbe:
				p.DialContext = dialer
			case *monitor.SSHProbe:
				p.DialContext = dialer
			case *monitor.DockerProbe:
				p.DialContext = dialer
			}

			if tunneler, ok := probe.(monitor.Tunneler); ok {
				tunneler.SetTunnel(t)
			}
		}
	}

	if init, ok := probe.(monitor.Initializer); ok {
		if err := init.Initialize(); err != nil {
			return nil, fmt.Errorf("[%s] early initialization failed: %w", svc.Name, err)
		}
	}

	targetMode := monitor.TargetModeAny
	if svc.TargetMode != "" {
		targetMode = svc.TargetMode
	}
	probe.SetTargetMode(targetMode)

	return probe, nil
}
