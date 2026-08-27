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
	ownsTunnel bool

	// newTunnel provides a small test seam for the inline-tunnel lifecycle.
	newTunnel func(string, *config.WireguardConfig) *tunnels.WireguardTunnel
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
	// Create an ephemeral tunnel if no root tunnel is provided
	newTunnel := p.newTunnel
	if newTunnel == nil {
		newTunnel = tunnels.NewWireguardTunnel
	}
	t := newTunnel("ephemeral", p.Config)
	p.tunnel = t
	p.ownsTunnel = true
	if err := t.Initialize(); err != nil {
		p.tunnel = nil
		p.ownsTunnel = false
		return err
	}
	t.StartSupervisor(context.Background())
	return nil
}

// Close releases an inline tunnel and its supervisor. Root tunnels are owned by
// the watchdog and are deliberately left running here.
func (p *WireguardProbe) Close() {
	if p.ownsTunnel && p.tunnel != nil {
		p.tunnel.Stop()
	}
	p.tunnel = nil
	p.ownsTunnel = false
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

	var dev tunnels.WGDevice
	var initTime time.Time
	if p.tunnel != nil {
		initTime = p.tunnel.LastInitTime()
		if wgTun, ok := p.tunnel.(interface{ Device() tunnels.WGDevice }); ok {
			dev = wgTun.Device()
		}
	}

	maxAge, err := p.resolveMaxAge()
	if err != nil {
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   err.Error(),
			Timestamp: start,
		}, nil
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
		p.tunnel.ReportFailure()
		return Result{
			Success:   false,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("failed to get handshake time: %v", err),
			Timestamp: start,
		}, nil
	}

	// Stabilization adherence: return Pending if tunnel not stabilized.
	// This prevents DOWN status during the restart window.
	if !p.tunnel.IsStabilized() {
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(start),
			Message:   fmt.Sprintf("waiting for handshake (stabilizing: %s passed)", time.Since(initTime).Round(time.Second)),
			Timestamp: start,
		}, nil
	}

	if lastHandshake.IsZero() {
		p.tunnel.ReportFailure()
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
		p.tunnel.ReportFailure()
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
	lines := strings.SplitSeq(uapi, "\n")
	for line := range lines {
		if after, ok := strings.CutPrefix(line, "last_handshake_time_sec="); ok {
			secStr := after
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

func (p *WireguardProbe) resolveMaxAge() (time.Duration, error) {
	if p.Config != nil && p.Config.MaxAge != "" {
		d, err := config.ParseDuration(p.Config.MaxAge)
		if err != nil {
			return 0, fmt.Errorf("invalid max_age: %v", err)
		}
		return d, nil
	}
	if p.tunnel == nil {
		return 0, nil
	}
	wgTun, ok := p.tunnel.(interface {
		Config() *config.WireguardConfig
	})
	if !ok {
		return 0, nil
	}
	if cfg := wgTun.Config(); cfg != nil && cfg.MaxAge != "" {
		d, err := config.ParseDuration(cfg.MaxAge)
		if err != nil {
			return 0, fmt.Errorf("invalid max_age from tunnel: %v", err)
		}
		return d, nil
	}
	return 0, nil
}

func (p *WireguardProbe) SetTimeout(timeout time.Duration) {
	// Not used for Wireguard probe
	_ = timeout
}
