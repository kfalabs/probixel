package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"probixel/pkg/tunnels"
)

type UDPProbe struct {
	// DialContext allows mocking the dialer for tests
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	Timeout     time.Duration
	targetMode  string
	tunnel      tunnels.Tunnel
}

func (p *UDPProbe) SetTunnel(t tunnels.Tunnel) {
	p.tunnel = t
}

func (p *UDPProbe) Name() string {
	return MonitorTypeUDP
}

func (p *UDPProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *UDPProbe) Check(ctx context.Context, target string) (Result, error) {
	// Support multiple targets (can be comma-separated or single)
	targets := strings.Split(target, ",")
	startTotal := time.Now()

	// Strict stabilization adherence: always return Pending if tunnel not stabilized
	if p.tunnel != nil && !p.tunnel.IsStabilized() {
		return Result{
			Success:   false,
			Pending:   true,
			Duration:  time.Since(startTotal),
			Message:   fmt.Sprintf("waiting for tunnel %q to stabilize", p.tunnel.Name()),
			Timestamp: startTotal,
		}, nil
	}

	// For "all" mode, track successes
	if p.targetMode == TargetModeAll {
		var totalDuration time.Duration
		successCount := 0

		for _, t := range targets {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}

			start := time.Now()
			var conn net.Conn
			var err error

			// Use mocked DialContext if available, else net.Dialer
			if p.DialContext != nil {
				conn, err = p.DialContext(ctx, "udp", t)
			} else {
				timeout := p.Timeout
				if timeout == 0 {
					timeout = 5 * time.Second
				}
				d := net.Dialer{Timeout: timeout}
				conn, err = d.DialContext(ctx, "udp", t)
			}

			if err != nil {
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}

			_, err = conn.Write([]byte{})
			_ = conn.Close()

			if err != nil {
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s write failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}

			totalDuration += time.Since(start)
			successCount++
		}

		if successCount > 0 {
			return Result{
				Success:   true,
				Duration:  totalDuration / time.Duration(successCount),
				Message:   fmt.Sprintf("all %d targets OK", successCount),
				Timestamp: startTotal,
			}, nil
		}
	}

	// Default "any" mode - return on first success
	var lastErr error
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		start := time.Now()
		var conn net.Conn
		var err error

		// Use mocked DialContext if available, else net.Dialer
		if p.DialContext != nil {
			conn, err = p.DialContext(ctx, "udp", t)
		} else {
			timeout := p.Timeout
			if timeout == 0 {
				timeout = 5 * time.Second
			}
			d := net.Dialer{Timeout: timeout}
			conn, err = d.DialContext(ctx, "udp", t)
		}

		if err != nil {
			lastErr = err
			continue
		}

		// For UDP, Dial just creates a socket then write something to check reachability/routing.
		// This doesn't guarantee the server receives it or replies, but it validates sendings.
		_, err = conn.Write([]byte{})
		_ = conn.Close()

		if err != nil {
			lastErr = err
			continue
		}

		// Success
		return Result{
			Success:   true,
			Duration:  time.Since(start),
			Message:   "OK",
			Target:    t,
			Timestamp: startTotal,
		}, nil
	}

	return Result{
		Success:   false,
		Duration:  0,
		Message:   fmt.Sprintf("all udp targets failed, last error: %v", lastErr),
		Timestamp: startTotal,
	}, nil
}
func (p *UDPProbe) SetTimeout(timeout time.Duration) {
	p.Timeout = timeout
}
