package monitor

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

type TCPProbe struct {
	// DialContext allows mocking the network connection. If nil, net.Dialer is used.
	DialContext func(ctx context.Context, network, address string) (net.Conn, error)
	targetMode  string
}

func (p *TCPProbe) Name() string {
	return MonitorTypeTCP
}

func (p *TCPProbe) SetTargetMode(mode string) {
	p.targetMode = mode
}

func (p *TCPProbe) Check(ctx context.Context, target string) (Result, error) {
	targets := strings.Split(target, ",")
	var lastErr error

	startTotal := time.Now()

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

			if p.DialContext != nil {
				conn, err = p.DialContext(ctx, "tcp", t)
			} else {
				d := net.Dialer{Timeout: 3 * time.Second}
				conn, err = d.DialContext(ctx, "tcp", t)
			}

			if err != nil {
				// In "all" mode, any failure means overall failure
				return Result{
					Success:   false,
					Duration:  0,
					Message:   fmt.Sprintf("target %s failed: %v", t, err),
					Timestamp: startTotal,
				}, nil
			}
			_ = conn.Close()
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
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}

		// Try to connect
		start := time.Now()
		var conn net.Conn
		var err error

		if p.DialContext != nil {
			conn, err = p.DialContext(ctx, "tcp", t)
		} else {
			d := net.Dialer{Timeout: 3 * time.Second}
			conn, err = d.DialContext(ctx, "tcp", t)
		}
		if err == nil {
			_ = conn.Close()
			return Result{
				Success:   true,
				Duration:  time.Since(start),
				Message:   "OK",
				Target:    t, // Return the specific target that worked
				Timestamp: startTotal,
			}, nil
		}
		lastErr = err
	}

	return Result{
		Success:   false,
		Duration:  0, // Duration is 0 on failure per bash script convention for "down 0"
		Message:   fmt.Sprintf("all targets failed, last error: %v", lastErr),
		Timestamp: startTotal,
	}, nil
}
