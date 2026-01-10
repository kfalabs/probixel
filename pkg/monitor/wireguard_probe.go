package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"

	"probixel/pkg/config"
	"probixel/pkg/tunnels"
)

type WGDevice interface {
	IpcGet() (string, error)
	IpcSet(conf string) error
	Close()
}

type WireguardProbe struct {
	Config     *config.WireguardConfig
	targetMode string
	tunnel     tunnels.Tunnel
	// Internal fields for manual config (no root tunnel)
	dev      tunnels.WGDevice
	initTime time.Time
}

func (p *WireguardProbe) SetTunnel(t tunnels.Tunnel) {
	if wgT, ok := t.(*tunnels.WireguardTunnel); ok {
		p.tunnel = wgT
	}
}

func (p *WireguardProbe) Name() string {
	return MonitorTypeWireguard
}

func (p *WireguardProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *WireguardProbe) Initialize() error {
	if p.tunnel != nil {
		return p.tunnel.Initialize()
	}
	if p.Config == nil {
		return fmt.Errorf("wireguard configuration missing")
	}
	if p.dev != nil {
		return nil
	}

	// Create an ephemeral tunnel if no root tunnel is provided
	t := tunnels.NewWireguardTunnel("ephemeral", p.Config)
	if err := t.Initialize(); err != nil {
		return err
	}
	p.dev = t.Device()
	p.initTime = t.LastInitTime()
	return nil
}

func (p *WireguardProbe) stop() {
	if p.tunnel != nil {
		p.tunnel.Stop()
		return
	}
	if p.dev != nil {
		p.dev.Close()
		p.dev = nil
	}
}

func (p *WireguardProbe) Check(ctx context.Context, target string) (Result, error) {
	start := time.Now()
	_ = target // WireGuard monitor is now heartbeat-only (ignores target)

	if p.Config == nil && p.tunnel == nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   "wireguard configuration missing",
			Timestamp: start,
		}, nil
	}

	dev := p.dev
	initTime := p.initTime
	if p.tunnel != nil {
		initTime = p.tunnel.LastInitTime()
		if wgTun, ok := p.tunnel.(interface{ Device() tunnels.WGDevice }); ok {
			dev = wgTun.Device()
		}
	}

	var maxAge time.Duration
	if p.Config != nil && p.Config.MaxAge != "" {
		var err error
		maxAge, err = config.ParseDuration(p.Config.MaxAge)
		if err != nil {
			return Result{
				Success:   false,
				Duration:  time.Since(start),
				Message:   fmt.Sprintf("invalid max_age: %v", err),
				Timestamp: start,
			}, nil
		}
	} else if p.tunnel != nil {
		if wgTun, ok := p.tunnel.(interface {
			Config() *config.WireguardConfig
		}); ok {
			if cfg := wgTun.Config(); cfg != nil && cfg.MaxAge != "" {
				var err error
				maxAge, err = config.ParseDuration(cfg.MaxAge)
				if err != nil {
					return Result{
						Success:   false,
						Duration:  time.Since(start),
						Message:   fmt.Sprintf("invalid max_age from tunnel: %v", err),
						Timestamp: start,
					}, nil
				}
			}
		}
	}


	if dev == nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   "wireguard device not initialized",
			Timestamp: start,
		}, nil
	}

	if maxAge == 0 {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   "wireguard.max_age is required for heartbeat check",
			Timestamp: start,
		}, nil
	}

	uapi, err := dev.IpcGet()
	if err != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to get handshake status: %v", err),
			Timestamp: start,
		}, nil
	}

	lastHandshake, err := parseLatestHandshake(uapi)
	if err != nil {
		if p.tunnel != nil {
			p.tunnel.ReportFailure()
		} else {
			p.stop()
		}
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to get handshake time: %v", err),
			Timestamp: start,
		}, nil
	}

	// Stabilization adherence: return Pending if tunnel not stabilized.
	// This prevents DOWN status during the 20s restart window.
	var isStabilized bool
	if p.tunnel != nil {
		isStabilized = p.tunnel.IsStabilized()
	} else {
		// Fallback to internal fixed 20s window if standalone
		gracePeriod := 20 * time.Second
		isStabilized = time.Since(initTime) >= gracePeriod
	}

	if !isStabilized {
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("waiting for handshake (stabilizing: %s passed)", time.Since(initTime).Round(time.Second)),
			Timestamp: start,
		}, nil
	}

	if lastHandshake.IsZero() {
		if p.tunnel != nil {
			p.tunnel.ReportFailure()
		} else {
			p.stop()
		}
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(start),
			Message:   "no handshake yet",
			Timestamp: start,
		}, nil
	}

	age := time.Since(lastHandshake)
	if age > maxAge {
		if p.tunnel != nil {
			p.tunnel.ReportFailure()
		} else {
			p.stop()
		}
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("handshake stale: %s (limit: %s)", age.Round(time.Second), maxAge),
			Timestamp: start,
		}, nil
	}

	if p.tunnel != nil {
		p.tunnel.ReportSuccess()
	}

	return Result{
		Success:   true,
		Duration:  time.Since(start),
		Message:   fmt.Sprintf("OK (last handshake %s ago)", age.Round(time.Second)),
		Timestamp: start,
	}, nil
}

func parseLatestHandshake(uapi string) (time.Time, error) {
	lines := strings.Split(uapi, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "last_handshake_time_sec=") {
			secStr := strings.TrimPrefix(line, "last_handshake_time_sec=")
			var sec int64
			if _, err := fmt.Sscanf(secStr, "%d", &sec); err != nil {
				return time.Time{}, err
			}
			if sec == 0 {
				return time.Time{}, nil
			}
			return time.Unix(sec, 0), nil
		}
	}
	return time.Time{}, nil
}

func (p *WireguardProbe) SetTimeout(timeout time.Duration) {
	// Not used for Wireguard probe
}
